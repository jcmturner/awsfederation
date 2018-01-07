package config

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/jcmturner/restclient"
	"github.com/jcmturner/vaultclient"
	krb5config "gopkg.in/jcmturner/gokrb5.v2/config"
	"gopkg.in/jcmturner/gokrb5.v2/keytab"
	"gopkg.in/ldap.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	TemplateJSON = `
{
	"Server": {
		"Socket": "%s",
		"TLS": {
			"Enabled": %t,
			"CertificateFile": "%s",
			"KeyFile": "%s"
		},
		"Authentication": {
			"Kerberos": {
				"Enabled": %t,
				"KeytabVaultPath": "%s",
				"ServiceAccount": "%s"
			},
			"Basic": {
				"Enabled": %t,
				"Realm": "%s",
				"Protocol": "%s",
				"Kerberos": {
					"KRB5ConfPath": "%s",
					"KeytabVaultPath": "%s",
					"ServiceAccount": "%s",
					"SPN": "%s"
				},
				"LDAP": {
					"EndPoint": "%s",
					"BaseDN": "%s",
					"UsernameAttribute": "%s",
					"UserObjectClass": "%s",
					"DisplayNameAttribute": "%s",
					"MembershipAttribute": "%s",
					"BindUserDN": "%s",
					"BindUserPasswordVaultPath": "%s",
					"TLSEnabled": %t,
					"TrustedCAPath": "%s"
				},
				"Static": {
					"RequiredSecret": "%s",
					"Attribute": "%s"
				}
			},
			"ActiveSessionTimeout": 15,
			"SessionDuration": 60
		},
		"Logging": {
			"Audit": "%s",
			"Application": "%s",
			"Access": "%s"
		}
	},
	"Vault": {
		"Config": {
			"SecretsRoot": "%s",
			"VaultConnection": {
				"EndPoint": "%s",
				"TrustCACert": "%s"
			}
		},
		"Credentials": {
			"AppID": "%s",
			"UserID": "%s",
			"UserIDFile": "%s"
		}

	},
	"Database": {
		"ConnectionString": "%s",
		"CredentialsVaultPath": "%s"
	}
}
`
	MockStaticSecret    = "mocktestsecret"
	MockStaticAttribute = "authzattrib"
)

type Config struct {
	Server   Server   `json:"Server"`
	Vault    Vault    `json:"Vault"`
	Database Database `json:"Database"`
}

type Vault struct {
	Config      *vaultclient.Config      `json:"Config"`
	Credentials *vaultclient.Credentials `json:"Credentials"`
}

type Server struct {
	Socket         string         `json:"Socket"`
	TLS            TLS            `json:"TLS"`
	Authentication Authentication `json:"Authentication"`
	Logging        *Loggers       `json:"Logging"`
}

type Database struct {
	ConnectionString     string `json:"ConnectionString"`
	CredentialsVaultPath string `json:"CredentialsVaultPath"`
}

type Authentication struct {
	Kerberos             Kerberos  `json:"Kerberos"`
	Basic                BasicAuth `json:"Basic"`
	JWT                  JWT       `json:"JWT"`
	ActiveSessionTimeout int       `json:"ActiveSessionTimeout"` // Duration in minutes
	SessionDuration      int       `json:"SessionDuration"`      // Duration in minutes
}

type Kerberos struct {
	Enabled         bool   `json:"Enabled"`
	KeytabVaultPath string `json:"KeytabVaultPath"`
	Keytab          *keytab.Keytab
	ServiceAccount  string `json:"ServiceAccount"`
}

type BasicAuth struct {
	Enabled  bool        `json:"Enabled"`
	Realm    string      `json:"Realm"`
	Protocol string      `json:"Protocol"` // Kerberos or LDAP or Static
	Kerberos KRB5Basic   `json:"Kerberos"`
	LDAP     LDAPBasic   `json:"LDAP"`
	Static   StaticBasic `json:"Static"`
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

type StaticBasic struct {
	RequiredSecret string `json:"RequiredSecret"`
	Attribute      string `json:"Attribute"`
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
		return &Config{}, fmt.Errorf("could not load configuration: %v", err)
	}
	return Parse(j)
}

func Parse(b []byte) (c *Config, err error) {
	c = NewConfig()
	err = json.Unmarshal(b, &c)
	if err != nil {
		err = fmt.Errorf("configuration file could not be parsed: %v", err)
		return
	}
	c.SetApplicationLogFile(c.Server.Logging.ApplicationFile)
	c.SetAuditLogFile(c.Server.Logging.AuditFile)
	c.SetAccessLogFile(c.Server.Logging.AccessLog)
	c.Vault.Config.ReSTClientConfig.WithCAFilePath(*c.Vault.Config.ReSTClientConfig.TrustCACert)
	if c.Vault.Credentials.UserID == "" {
		err = c.Vault.Credentials.ReadUserID()
		if err != nil {
			err = fmt.Errorf("error configuring vault client: %v", err)
			c.ApplicationLogf(err.Error())
			return
		}
	}
	return
}

func NewConfig() *Config {
	dl := log.New(os.Stdout, "AWS Federation Server: ", log.Ldate|log.Ltime)
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
		c.ApplicationLogf("invalid listener socket defined for server: %v\n", err)
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

func (c *Config) SetVault(addr, caFilePath, appID, userID, secretsRoot string) *Config {
	vConf := vaultclient.Config{
		SecretsPath:      secretsRoot,
		ReSTClientConfig: *restclient.NewConfig().WithEndPoint(addr),
	}
	if caFilePath != "" {
		vConf.ReSTClientConfig.WithCAFilePath(caFilePath)
	}

	vCreds := vaultclient.Credentials{
		AppID:  appID,
		UserID: userID,
	}

	c.Vault = Vault{
		Config:      &vConf,
		Credentials: &vCreds,
	}
	return c
}

func (c *Config) logWriter(p string) (w io.Writer, err error) {
	switch strings.ToLower(p) {
	case "":
		err = errors.New("log destination not specified, defaulting to stdout")
		w = os.Stdout
		//l = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
	case "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	case "null":
		w = ioutil.Discard
	default:
		w, err = os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	}
	return
}

func (c *Config) SetAuditLogger(e *json.Encoder) *Config {
	c.Server.Logging.AuditEncoder = e
	return c
}

func (c *Config) SetAuditLogFile(p string) *Config {
	w, err := c.logWriter(p)
	if err != nil {
		c.ApplicationLogf("could not open audit log file: %v\n", err)
	}
	c.Server.Logging.AuditFile = p
	enc := json.NewEncoder(w)
	c.SetAuditLogger(enc)
	return c
}

func (c *Config) SetApplicationLogger(l *log.Logger) *Config {
	c.Server.Logging.ApplicationLogger = l
	return c
}

func (c *Config) SetApplicationLogFile(p string) *Config {
	w, err := c.logWriter(p)
	if err != nil {
		c.ApplicationLogf("could not open application log file: %v\n", err)
	}
	c.Server.Logging.ApplicationFile = p
	l := log.New(w, "AWS Federation Server: ", log.Ldate|log.Ltime)
	c.SetApplicationLogger(l)
	return c
}

func (c *Config) SetAccessLogFile(p string) *Config {
	w, err := c.logWriter(p)
	if err != nil {
		c.ApplicationLogf("could not open access log file: %v\n", err)
	}
	c.Server.Logging.AccessLog = p
	enc := json.NewEncoder(w)
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
	if c.Server.Logging.AccessEncoder != nil {
		err := c.Server.Logging.AccessEncoder.Encode(v)
		if err != nil {
			c.ApplicationLogf("could not log access event: %+v - Error: %v\n", err)
		}
	}
}

func (c Config) AuditLog(v interface{}) {
	if c.Server.Logging.AuditEncoder != nil {
		err := c.Server.Logging.AuditEncoder.Encode(v)
		if err != nil {
			c.ApplicationLogf("could not log audit event: %+v - Error: %v\n", err)
		}
	}
}

func (c Config) ApplicationLogf(format string, v ...interface{}) {
	if c.Server.Logging.ApplicationLogger == nil {
		l := log.New(os.Stdout, "AWS Federation Server: ", log.Ldate|log.Ltime)
		c.Server.Logging.ApplicationLogger = l
	}
	c.Server.Logging.ApplicationLogger.Printf(format, v)
}

func (c Config) Summary() string {
	return fmt.Sprintf(`AWS Federation Server Configuration:
	Listenning Socket: %s
	HTTPS Enabled: %v
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
		return fmt.Errorf("could not read PEM file: %v", err)
	}
	block, rest := pem.Decode(pemData)
	if len(rest) > 0 || block.Type == "" {
		return fmt.Errorf("invalid PEM format: Rest: %v Type: %v", len(rest), block.Type)
	}
	return nil
}

// Mock returns a minimal config for testing
func Mock() (*Config, string) {
	confJSON := fmt.Sprintf(TemplateJSON,
		// Server level config
		"127.0.0.1:8443", false, "", "",
		// Kerberos SPNEGO config
		false, "", "",
		// Basic auth config
		true, "", "static",
		// Kerberos basic auth config
		"", "", "", "",
		// LDAP basic auth config
		"", "", "", "", "", "", "", "", false, "",
		// Static basic used for testing
		MockStaticSecret, MockStaticAttribute,
		// Logging config
		"null", "stderr", "null",
		// Vault config
		"secret", "https://127.0.0.1:9200", "", "", "userid", "",
		// Database config
		"127.0.0.1:3306", "database")
	c, err := Parse([]byte(confJSON))
	if err != nil {
		// Can panic as this should only be used in tests!!!
		panic(fmt.Sprintf("%v: %s", err, confJSON))
	}
	return c, confJSON
}

func IntgTest() *Config {
	c, _ := Mock()
	dbs := os.Getenv("TEST_DB_SOCKET")
	if dbs == "" {
		dbs = "127.0.0.1:3306"
	}
	c.Database.ConnectionString = fmt.Sprintf("${username}:${password}@tcp(%s)/awsfederation?multiStatements=true&parseTime=true&autocommit=true&charset=utf8&timeout=90s", dbs)
	addr := os.Getenv("TEST_VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	c.SetVault(addr, "", "6a1ab78a-0f5b-4287-9371-cca1fc70b0f1", "06ba5ac6-3d85-43df-81b5-cf56f4f4624e", "/secret/")
	return c
}
