package config

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/restclient"
	"github.com/jcmturner/vaultclient"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type Config struct {
	Server       Server `json:"Server"`
	Vault        Vault  `json:"Vault"`
	FedUserCache *FedUserCache
}

type Vault struct {
	Config      *vaultclient.Config      `json:"Config"`
	Credentials *vaultclient.Credentials `json:"Credentials"`
}

type Server struct {
	Socket  string   `json:"Socket"`
	TLS     TLS      `json:"TLS"`
	Logging *Loggers `json:"Logging"`
}

type TLS struct {
	Enabled         bool   `json:"Enabled"`
	CertificateFile string `json:"CertificateFile"`
	KeyFile         string `json:"KeyFile"`
}

type Loggers struct {
	AuditFile         string `json:"Audit"`
	AuditLogger       *log.Logger
	ApplicationFile   string `json:"Application"`
	ApplicationLogger *log.Logger
}

type FedUserCache map[string]*federationuser.FederationUser

func Load(cfgPath string) (*Config, error) {
	j, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		return &Config{}, fmt.Errorf("Could not load configuration: %v", err)
	}
	c := NewConfig()
	err = json.Unmarshal(j, &c)
	if err != nil {
		return &Config{}, fmt.Errorf("Configuration file could not be parsed: %v", err)
	}
	c.SetApplicationLogFile(c.Server.Logging.ApplicationFile)
	c.SetAuditLogFile(c.Server.Logging.AuditFile)
	err = c.Vault.Credentials.ReadUserID()
	if err != nil {
		c.ApplicationLogf(err.Error())
		return &Config{}, fmt.Errorf("Error configuring vault client: %v", err)
	}
	return c, nil
}

func NewConfig() *Config {
	dl := log.New(os.Stdout, "AWS Federation Server: ", log.Ldate|log.Ltime|log.Lshortfile)
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
				AuditLogger:       dl,
				ApplicationLogger: dl,
			},
		},
		FedUserCache: make(FedUserCache),
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

func (c *Config) SetAuditLogger(l *log.Logger) *Config {
	c.Server.Logging.AuditLogger = l
	return c
}

func (c *Config) SetAuditLogFile(p string) *Config {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0440)
	if err != nil {
		c.ApplicationLogf("Could not open audit log file: %v\n", err)
	}
	l := log.New(f, "Audit Log: ", log.Ldate|log.Ltime|log.Lshortfile)
	c.Server.Logging.AuditFile = p
	c.SetAuditLogger(l)
	return c
}

func (c *Config) SetApplicationLogger(l *log.Logger) *Config {
	c.Server.Logging.ApplicationLogger = l
	return c
}

func (c *Config) SetApplicationLogFile(p string) *Config {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0444)
	if err != nil {
		c.ApplicationLogf("Could not open application log file: %v\n", err)
	}
	l := log.New(f, "Application Log: ", log.Ldate|log.Ltime|log.Lshortfile)
	c.Server.Logging.ApplicationFile = p
	c.SetApplicationLogger(l)
	return c
}

func (c *Config) ToString() string {
	// Format back into JSON but remove userID
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

func (c Config) AuditLogf(format string, v ...interface{}) {
	if c.Server.Logging.AuditLogger != nil {
		c.Server.Logging.AuditLogger.Printf(format, v)
	}
}

func (c Config) ApplicationLogf(format string, v ...interface{}) {
	if c.Server.Logging.ApplicationLogger == nil {
		l := log.New(os.Stdout, "AWS Federation Server: ", log.Ldate|log.Ltime|log.Lshortfile)
		c.Server.Logging.ApplicationLogger = l
	}
	c.Server.Logging.ApplicationLogger.Printf(format, v)
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
