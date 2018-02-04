package app

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/awsfederation/httphandling"
	"github.com/jcmturner/vaultclient"
	krb5config "gopkg.in/jcmturner/gokrb5.v4/config"
	"gopkg.in/jcmturner/gokrb5.v4/keytab"
	"gopkg.in/ldap.v2"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	appUser     = "awsfedapp"
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!£%^*()[]{}<>.|"
)

var buildhash = "Not set"
var buildtime = "Not set"
var version = "Not set"

type App struct {
	Router        *mux.Router
	Config        *config.Config
	FedUserCache  *federationuser.FedUserCache
	DB            *sql.DB
	PreparedStmts *database.StmtMap
	VaultClient   *vaultclient.Client
}

func Version() (string, string, time.Time) {
	bt, _ := time.Parse(time.RFC3339, buildtime)
	return version, buildhash, bt
}

func generatePasswd() string {
	b := make([]byte, 20)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func ApplyDBSchema(c *config.Config, dbSocket, dbAdminUser, dbAdminPasswd string) error {
	//TODO make this work with a TLS DB connection
	//dbs := fmt.Sprintf("%s:%s@tcp(%s)/dbname?tls=skip-verify&multiStatements=true&parseTime=true&autocommit=true&charset=utf8&timeout=90s", dbAdminUser, dbAdminPasswd, dbSocket)
	dbs := fmt.Sprintf("%s:%s@tcp(%s)/?multiStatements=true&parseTime=true&autocommit=true&charset=utf8&timeout=90s", dbAdminUser, dbAdminPasswd, dbSocket)
	db, err := sql.Open("mysql", dbs)
	if err != nil {
		return err
	}
	defer db.Close()
	appPasswd := generatePasswd()
	if err != nil {
		return fmt.Errorf("could not generate random password: %v", err)
	}
	_, err = db.Exec(fmt.Sprintf(database.DBCreateSchemaAppUser, appUser, appPasswd, appUser))
	if err != nil {
		return err
	}

	// Store the database password in vault
	cl, err := vaultclient.NewClient(c.Vault.Config, c.Vault.Credentials)
	if err != nil {
		return err
	}
	m := make(map[string]interface{})
	m["username"] = appUser
	m["password"] = appPasswd
	cl.Write(c.Database.CredentialsVaultPath, m)

	_, err = db.Exec(database.DBCreateTables)
	if err != nil {
		return err
	}
	bt, err := time.Parse(time.RFC3339, buildtime)
	if err != nil {
		return fmt.Errorf("format of buildtime set during compliation is not correct. It must confirm to RFC3339: %v", err)
	}
	_, err = db.Exec("INSERT INTO metadata(datetime, version, buildhash, buildtime) VALUES (?, ?, ?, ?)", time.Now().UTC(), version, buildhash, bt)
	if err != nil {
		return err
	}
	return nil
}

func (a *App) Initialize(c *config.Config) error {
	a.Config = c

	// Initialise the Vault Client
	vc, err := vaultclient.NewClient(c.Vault.Config, c.Vault.Credentials)
	if err != nil {
		return fmt.Errorf("error creating vault client: %v", err)
	}
	a.VaultClient = &vc

	// Initialise authentication config
	if c.Server.Authentication.Kerberos.Enabled {
		if c.Server.Authentication.Kerberos.KeytabVaultPath == "" {
			return errors.New("kerberos authentication enabled but no path to keytab in vault defined")
		}
		var kt keytab.Keytab
		kt, err = loadKeytabFromVault(c.Vault.Config.SecretsPath+c.Server.Authentication.Kerberos.KeytabVaultPath, a.VaultClient)
		if err != nil {
			err = fmt.Errorf("error loading keytab for kerberos authentication from vault: %v", err)
			c.ApplicationLogf(err.Error())
			return err
		}
		c.Server.Authentication.Kerberos.Keytab = &kt
	}
	if c.Server.Authentication.Basic.Enabled {
		switch strings.ToLower(c.Server.Authentication.Basic.Protocol) {
		case "ldap":
			c.Server.Authentication.Basic.LDAP.BindUserPassword, err = loadLDAPBindPasswordFromVault(c.Server.Authentication.Basic.LDAP.BindUserPasswordVaultPath, a.VaultClient)
			if err != nil {
				err = fmt.Errorf("error loading LDAP bind password from vault: %v", err)
				c.ApplicationLogf(err.Error())
				return err
			}
			var lc *ldap.Conn
			lc, err = ldapConn(c.Server.Authentication.Basic.LDAP)
			if err != nil {
				err = fmt.Errorf("error getting LDAP connection: %v", err)
				c.ApplicationLogf(err.Error())
				return err
			}
			c.Server.Authentication.Basic.LDAP.LDAPConn = lc
		case "kerberos":
			c.Server.Authentication.Basic.Kerberos.Conf, err = krb5config.Load(c.Server.Authentication.Basic.Kerberos.KRB5ConfPath)
			if err != nil {
				err = fmt.Errorf("invalid kerberos basic authentication configuration: %v", err)
				c.ApplicationLogf(err.Error())
				return err
			}
			var kt keytab.Keytab
			kt, err = loadKeytabFromVault(c.Vault.Config.SecretsPath+c.Server.Authentication.Basic.Kerberos.KeytabVaultPath, a.VaultClient)
			if err != nil {
				err = errors.New("error loading keytab for kerberos basic authentication from vault: %v")
				c.ApplicationLogf(err.Error())
				return err
			}
			c.Server.Authentication.Basic.Kerberos.Keytab = &kt
		case "static":
			if c.Server.Authentication.Basic.Static.RequiredSecret == "" {
				err = errors.New("static authentication configured without a required secret")
			}
		default:
			err = fmt.Errorf("invalid protocol (%v) for basic authentication", c.Server.Authentication.Basic.Protocol)
			c.ApplicationLogf(err.Error())
			return err
		}
	}

	// Set up the database connection
	dbs := c.Database.ConnectionString
	dbm, err := a.VaultClient.Read(c.Database.CredentialsVaultPath)
	if err != nil {
		return fmt.Errorf("failed to load database credentials from the vault: %v", err)
	}
	if v, ok := dbm["username"]; ok {
		dbs = strings.Replace(dbs, "${username}", v.(string), -1)
	}
	if v, ok := dbm["password"]; ok {
		dbs = strings.Replace(dbs, "${password}", v.(string), -1)
	}
	a.DB, err = sql.Open("mysql", dbs)
	if err != nil {
		return fmt.Errorf("failed to open database: %v\n", err)
	}
	if err := a.DB.Ping(); err != nil {
		return fmt.Errorf("database connection test failed: %v\n", err)
	}

	// Prepare and store DB statements
	a.PreparedStmts, err = database.NewStmtMap(a.DB)
	if err != nil {
		return fmt.Errorf("error preparing database statements: %v", err)
	}

	// Initialise the HTTP router
	a.Router = httphandling.NewRouter(a.Config, a.PreparedStmts, a.FedUserCache)

	return nil
}

func (a *App) Run() (err error) {
	v, bh, bt := Version()
	fmt.Fprintf(os.Stderr, "AWS Federation Version Information:\nVersion:\t%s\nBuild hash:\t%s\nBuild time:\t%v\n", v, bh, bt)
	fmt.Fprintln(os.Stderr, a.Config.Summary())
	// Deferred clean up actions
	//
	defer a.DB.Close()
	// Start server
	if a.Config.Server.TLS.Enabled {
		err = http.ListenAndServeTLS(a.Config.Server.Socket, a.Config.Server.TLS.CertificateFile, a.Config.Server.TLS.KeyFile, a.Router)
	} else {
		err = http.ListenAndServe(a.Config.Server.Socket, a.Router)
	}
	return
}

func loadKeytabFromVault(p string, vc *vaultclient.Client) (kt keytab.Keytab, err error) {
	m, e := vc.Read(p)
	if err != nil {
		err = e
		return
	}
	if khex, ok := m["keytab"]; ok {
		var kb []byte
		kb, err = hex.DecodeString(khex.(string))
		if err != nil {
			return
		}
		kt, err = keytab.Parse(kb)
		if err != nil {
			return
		}
		return
	}
	err = errors.New("keytab not found in vault")
	return
}

func ldapConn(l config.LDAPBasic) (c *ldap.Conn, err error) {
	if l.EndPoint == "" {
		err = errors.New("LDAP endpoint not defined")
	}
	if l.TLSEnabled {
		if l.TrustedCAPath == "" {
			err = errors.New("trusted CA for LDAPS connection not defined")
			return
		}
		cp := x509.NewCertPool()
		// Load our trusted certificate path
		pemData, e := ioutil.ReadFile(l.TrustedCAPath)
		if err != nil {
			err = fmt.Errorf("CA certificate for LDAP could not be read from file: %v", e)
			return
		}
		ok := cp.AppendCertsFromPEM(pemData)
		if !ok {
			err = fmt.Errorf("CA certificate for LDAP could not be loaded from file, is it PEM format? %v", err)
			return
		}
		tlsConfig := &tls.Config{RootCAs: cp}
		c, err = ldap.DialTLS("tcp", l.EndPoint, tlsConfig)
		return
	}
	c, err = ldap.Dial("tcp", l.EndPoint)
	return
}

func loadLDAPBindPasswordFromVault(p string, vc *vaultclient.Client) (passwd string, err error) {
	m, err := vc.Read(p)
	if err != nil {
		return
	}
	if pswd, ok := m["password"]; ok {
		passwd = pswd.(string)
		return
	}
	err = errors.New("LDAP bind password not found in vault")
	return
}
