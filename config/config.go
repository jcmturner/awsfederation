package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	krb5config "github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/restclient"
	"github.com/jcmturner/vaultclient"
	"gopkg.in/ldap.v2"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	Server         Server         `json:"Server"`
	Vault          Vault          `json:"Vault"`
	Database       Database       `json:"Database"`
	Authentication Authentication `json:"Authenticaiton"`
}

type Vault struct {
	Config      *vaultclient.Config      `json:"Config"`
	Credentials *vaultclient.Credentials `json:"Credentials"`
	Client      *vaultclient.Client
}

type Server struct {
	Socket  string   `json:"Socket"`
	TLS     TLS      `json:"TLS"`
	Logging *Loggers `json:"Logging"`
}

type Database struct {
	ConnectionString     string `json:"ConnectionString"`
	CredentialsVaultPath string `json:"CredentialsVaultPath"`
}

type Authentication struct {
	Kerberos Kerberos  `json:"Kerberos"`
	Basic    BasicAuth `json:"Basic"`
	JWT      JWT       `json:"JWT"`
}

type Kerberos struct {
	Enabled         bool   `json:"Enabled"`
	KeytabVaultPath string `json:"KeytabVaultPath"`
	Keytab          *keytab.Keytab
	ServiceAccount  string `json:"ServiceAccount"`
}

type BasicAuth struct {
	Enabled  bool      `json:"Enabled"`
	Realm    string    `json:"Realm"`
	Protocol string    `json:"Protocol"` // Kerberos or LDAP
	Kerberos KRB5Basic `json:"Kerberos"`
	LDAP     LDAPBasic `json:"LDAP"`
}

type LDAPBasic struct {
	EndPoint                  string `json:"EndPoint"`
	BaseDN                    string `json:"BaseDN"`
	UsernameAttribute         string `json:"UsernameAttribute"` // "cn" "sAMAccountName"
	UserObjectClass           string `json:"UserObjectClass"`
	DisplayNameAttribute      string `json:"DisplayNameAttribute"`
	MembershipAttribute       string `json:"MembershipAttribute"`
	BindUserDN                string `json:"BindUserDN"`
	BindUserPasswordVaultPath string `json:"BindUserPasswordVaultPath"`
	BindUserPassword          string
	TLSEnabled                bool   `json:"TLSEnabled"`
	TrustedCAPath             string `json:"TrustedCAPath"`
	LDAPConn                  *ldap.Conn
}

type KRB5Basic struct {
	KRB5ConfPath    string `json:"KRB5ConfPath"`
	Conf            *krb5config.Config
	KeytabVaultPath string `json:"KeytabVaultPath"`
	Keytab          *keytab.Keytab
	ServiceAccount  string `json:"ServiceAccount"`
	SPN             string `json:"SPN"`
}

type JWT struct {
	Enabled bool `json:"Enabled"`
}

type TLS struct {
	Enabled         bool   `json:"Enabled"`
	CertificateFile string `json:"CertificateFile"`
	KeyFile         string `json:"KeyFile"`
}

type Loggers struct {
	AuditFile         string `json:"Audit"`
	AuditEncoder      *json.Encoder
	ApplicationFile   string `json:"Application"`
	ApplicationLogger *log.Logger
	AccessLog         string `json:"Access"`
	AccessEncoder     *json.Encoder
}

type AuditLogLine struct {
	Username      string    `json:"Username"`
	UserDomain    string    `json:"UserDomain"`
	UserSessionID string    `json:"UserSessionID"`
	Time          time.Time `json:"Time"`
	EventType     string    `json:"EventType"`
	UUID          string    `json:"EventUUID"`
	Detail        string    `json:"Detail"`
}

func Load(cfgPath string) (*Config, error) {
	j, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		return &Config{}, fmt.Errorf("Could not load configuration: %v", err)
	}
	return Parse(j)
}

func Parse(b []byte) (c *Config, err error) {
	c = NewConfig()
	err = json.Unmarshal(b, &c)
	if err != nil {
		err = fmt.Errorf("Configuration file could not be parsed: %v", err)
		return
	}
	c.SetApplicationLogFile(c.Server.Logging.ApplicationFile)
	c.SetAuditLogFile(c.Server.Logging.AuditFile)
	c.SetAccessLogFile(c.Server.Logging.AccessLog)
	c.Vault.Config.ReSTClientConfig.WithCAFilePath(*c.Vault.Config.ReSTClientConfig.TrustCACert)
	err = c.Vault.Credentials.ReadUserID()
	if err != nil {
		err = fmt.Errorf("error configuring vault client: %v", err)
		c.ApplicationLogf(err.Error())
		return
	}
	vc, err := vaultclient.NewClient(c.Vault.Config, c.Vault.Credentials)
	c.Vault.Client = &vc
	if c.Authentication.Kerberos.Enabled {
		if c.Authentication.Kerberos.KeytabVaultPath == "" {
			err = errors.New("kerberos authentication enabled but no path to keytab in vault defined")
		}
		var kt keytab.Keytab
		kt, err = loadKeytabFromVault(c.Authentication.Kerberos.KeytabVaultPath, c.Vault.Client)
		if err != nil {
			err = errors.New("error loading keytab for kerberos authentication from vault: %v")
			c.ApplicationLogf(err.Error())
			return
		}
		c.Authentication.Kerberos.Keytab = &kt
	}
	if c.Authentication.Basic.Enabled {
		switch strings.ToLower(c.Authentication.Basic.Protocol) {
		case "ldap":
			c.Authentication.Basic.LDAP.BindUserPassword, err = loadLDAPBindPasswordFromVault(c.Authentication.Basic.LDAP.BindUserPasswordVaultPath, c.Vault.Client)
			if err != nil {
				err = fmt.Errorf("error loading LDAP bind password from vault: %v", err)
				c.ApplicationLogf(err.Error())
				return
			}
			var lc *ldap.Conn
			lc, err = ldapConn(c.Authentication.Basic.LDAP)
			if err != nil {
				err = fmt.Errorf("error getting LDAP connection: %v", err)
				c.ApplicationLogf(err.Error())
				return
			}
			c.Authentication.Basic.LDAP.LDAPConn = lc
		case "kerberos":
			c.Authentication.Basic.Kerberos.Conf, err = krb5config.Load(c.Authentication.Basic.Kerberos.KRB5ConfPath)
			if err != nil {
				err = fmt.Errorf("Invalid Kerberos configuration. Basic authentication disabled: %v", err)
				c.ApplicationLogf(err.Error())
				return
			}
			var kt keytab.Keytab
			kt, err = loadKeytabFromVault(c.Authentication.Basic.Kerberos.KeytabVaultPath, c.Vault.Client)
			if err != nil {
				err = errors.New("error loading keytab for kerberos basic authentication from vault: %v")
				c.ApplicationLogf(err.Error())
				return
			}
			c.Authentication.Basic.Kerberos.Keytab = &kt
		default:
			err = fmt.Errorf("Invalid protocol (%v) for basic authentication. Basic authentication disabled.", c.Authentication.Basic.Protocol)
			c.ApplicationLogf(err.Error())
			return
		}
	}
	return
}

func NewConfig() *Config {
	dl := log.New(os.Stdout, "AWS Federation Server: ", log.Ldate|log.Ltime|log.Lshortfile)
	je := json.NewEncoder(os.Stdout)
	return &Config{
		Vault: Vault{
			Config: &vaultclient.Config{
				SecretsPath:      "/secret/",
				ReSTClientConfig: *restclient.NewConfig().WithEndPoint("127.0.0.1:8200"),
			},
			Credentials: &vaultclient.Credentials{},
		},
		Server: Server{
			Socket: "0.0.0.0:8443",
			Logging: &Loggers{
				AuditEncoder:      je,
				ApplicationLogger: dl,
				AccessEncoder:     je,
			},
		},
	}
}

func (c *Config) SetSocket(s string) *Config {
	if _, err := net.ResolveTCPAddr("tcp", s); err != nil {
		c.ApplicationLogf("Invalid listener socket defined for server: %v\n", err)
		return c
	}
	c.Server.Socket = s
	return c
}

func (c *Config) SetTLS(tlsConf TLS) *Config {
	if err := isKeyPairVaild(tlsConf.CertificateFile, tlsConf.KeyFile); err != nil {
		c.ApplicationLogf("%s\n", err)
	}
	c.Server.TLS = tlsConf
	return c
}

func (c *Config) SetAuditLogger(e *json.Encoder) *Config {
	c.Server.Logging.AuditEncoder = e
	return c
}

func (c *Config) SetAuditLogFile(p string) *Config {
	if p == "" {
		return c
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		c.ApplicationLogf("Could not open audit log file: %v\n", err)
	}
	c.Server.Logging.AuditFile = p
	enc := json.NewEncoder(f)
	c.SetAuditLogger(enc)
	return c
}

func (c *Config) SetApplicationLogger(l *log.Logger) *Config {
	c.Server.Logging.ApplicationLogger = l
	return c
}

func (c *Config) SetApplicationLogFile(p string) *Config {
	if p == "" {
		return c
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		c.ApplicationLogf("Could not open application log file: %v\n", err)
	}
	l := log.New(f, "Application Log: ", log.Ldate|log.Ltime|log.Lshortfile)
	c.Server.Logging.ApplicationFile = p
	c.SetApplicationLogger(l)
	return c
}

func (c *Config) SetAccessLogFile(p string) *Config {
	if p == "" {
		return c
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		c.ApplicationLogf("Could not open access log file: %v\n", err)
	}
	c.Server.Logging.AccessLog = p
	enc := json.NewEncoder(f)
	c.SetAccessEncoder(enc)
	return c
}

func (c *Config) SetAccessEncoder(e *json.Encoder) *Config {
	c.Server.Logging.AccessEncoder = e
	return c
}

func (c *Config) ToString() string {
	//TODO Format back into JSON but remove userID
	return ""
}

func NewTLSConfig(cert, key string) (TLS, error) {
	if err := isKeyPairVaild(cert, key); err != nil {
		return TLS{}, err
	} else {
		return TLS{
			Enabled:         true,
			CertificateFile: cert,
			KeyFile:         key,
		}, nil
	}
}

func (c Config) AccessLog(v interface{}) {
	if c.Server.Logging.AuditEncoder != nil {
		err := c.Server.Logging.AccessEncoder.Encode(v)
		if err != nil {
			c.ApplicationLogf("Could not log access event: %+v - Error: %v\n", err)
		}
	}
}

func (c Config) AuditLog(v interface{}) {
	if c.Server.Logging.AuditEncoder != nil {
		err := c.Server.Logging.AuditEncoder.Encode(v)
		if err != nil {
			c.ApplicationLogf("Could not log audit event: %+v - Error: %v\n", err)
		}
	}
}

func (c Config) ApplicationLogf(format string, v ...interface{}) {
	if c.Server.Logging.ApplicationLogger == nil {
		l := log.New(os.Stdout, "AWS Federation Server: ", log.Ldate|log.Ltime|log.Lshortfile)
		c.Server.Logging.ApplicationLogger = l
	}
	c.Server.Logging.ApplicationLogger.Printf(format, v)
}

func (c Config) Summary() string {
	return fmt.Sprintf(`AWS Federation Server Configuration:
	Listenning Socket: %s
	HTTP Enabled: %v
	Log Files:
		Application: %s
		Audit: %s
		Access: %s
	Vault:
		URL: %s
		Secrets Path: %s
`,
		c.Server.Socket,
		c.Server.TLS.Enabled,
		c.Server.Logging.ApplicationFile,
		c.Server.Logging.AuditFile,
		c.Server.Logging.AccessLog,
		*c.Vault.Config.ReSTClientConfig.EndPoint,
		c.Vault.Config.SecretsPath,
	)
}

func isKeyPairVaild(cert, key string) error {
	if err := isValidPEMFile(cert); err != nil {
		return fmt.Errorf("Server TLS certificate not valid: %v", err)
	}
	if err := isValidPEMFile(key); err != nil {
		return fmt.Errorf("Server TLS key not valid: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		return fmt.Errorf("Key pair provided not valid: %v", err)
	}
	return nil
}

func isValidPEMFile(p string) error {
	pemData, err := ioutil.ReadFile(p)
	if err != nil {
		return fmt.Errorf("Could not read PEM file: %v", err)
	}
	block, rest := pem.Decode(pemData)
	if len(rest) > 0 || block.Type == "" {
		return fmt.Errorf("Not valid PEM format: Rest: %v Type: %v", len(rest), block.Type)
	}
	return nil
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
	err = errors.New("Keytab not found in vault")
	return
}

func ldapConn(l LDAPBasic) (c *ldap.Conn, err error) {
	if l.EndPoint == "" {
		err = errors.New("LDAP endpoint not defined")
	}
	if l.TLSEnabled {
		if l.TrustedCAPath == "" {
			err = errors.New("Trusted CA for LDAPS connection not defined")
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
