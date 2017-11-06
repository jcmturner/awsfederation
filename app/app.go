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
	krb5config "gopkg.in/jcmturner/gokrb5.v2/config"
	"gopkg.in/jcmturner/gokrb5.v2/keytab"
	"gopkg.in/ldap.v2"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type App struct {
	Router        *mux.Router
	Config        *config.Config
	FedUserCache  *federationuser.FedUserCache
	DB            *sql.DB
	PreparedStmts *database.StmtMap
	VaultClient   *vaultclient.Client
}

func (a *App) Initialize(c *config.Config) error {
	a.Config = c

	// Initialise the HTTP router
	a.Router = httphandling.NewRouter(a.Config, a.PreparedStmts, a.FedUserCache)

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
	return nil
}

func (a *App) Run() (err error) {
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
