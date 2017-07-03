package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

const (
	TestJSON = `
{
	"Server": {
		"Socket": "%s",
		"TLS": {
			"Enabled": true,
			"CertificateFile": "%s",
			"KeyFile": "%s"
		},
		"Logging": {
			"Audit": "%s",
			"Application": "%s"
		}
	},
	"Vault": {
		"Config": {
			"SecretsPath": "/testsecret/",
			"VaultConnection": {
				"EndPoint": "%s",
				"TrustCACert": "%s"
			}
		},
		"Credentials": {
			"AppID": "0f9ef666-cdd9-4176-8c69-2d456be86ac0",
			"UserID": "09f28d61-67c0-4587-82f6-e2df56a1b075",
			"UserIDFile": "%s"
		}

	}
}
`
)

func TestLoad(t *testing.T) {
	certPath, keyPath, certBytes, _ := GenerateSelfSignedTLSKeyPairFiles(t)
	//Have to add test cert into a certPool to compare in the assertion as this is all we can get back from the TLSClientConfig of the http.Client and certPool has no public mechanism to extract certs from it
	cert, _ := x509.ParseCertificate(certBytes)
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	//Create temp userid file
	f, _ := ioutil.TempFile(os.TempDir(), "userid")
	defer os.Remove(f.Name())
	userid := "0ecd7b5d-4885-45c1-a03f-5949e485c6bf"
	u := fmt.Sprintf(`{
	"UserId": "%s"
	}`, userid)
	f.WriteString(u)
	f.Close()

	auditLog, _ := ioutil.TempFile(os.TempDir(), "mockAuditlogfile")
	defer os.Remove(auditLog.Name())
	auditLog.Close()
	appLog, _ := ioutil.TempFile(os.TempDir(), "mockApplogfile")
	defer os.Remove(appLog.Name())
	appLog.Close()

	ls := "127.0.0.1:9443"
	ep := "https://127.0.0.1:8200"

	completeJson := fmt.Sprintf(TestJSON, ls, certPath, keyPath, auditLog.Name(), appLog.Name(), ep, certPath, f.Name())

	testConfigFile, _ := ioutil.TempFile(os.TempDir(), "config")
	defer os.Remove(testConfigFile.Name())
	testConfigFile.WriteString(completeJson)
	testConfigFile.Close()
	c, err := Load(testConfigFile.Name())
	if err != nil {
		t.Fatalf("Error loading configuration JSON: %v", err)
	}
	t.Logf("Config: %+v\n", *c)
	assert.Equal(t, ls, c.Server.Socket, "Server socket not as expected")
	assert.Equal(t, true, c.Server.TLS.Enabled, "TLS note enabled")
	assert.Equal(t, certPath, c.Server.TLS.CertificateFile, "Server certificate not as expected")
	assert.Equal(t, keyPath, c.Server.TLS.KeyFile, "Server key file not as expected")
	assert.Equal(t, auditLog.Name(), c.Server.Logging.AuditFile, "Audit log filename not as expected")
	assert.Equal(t, appLog.Name(), c.Server.Logging.ApplicationFile, "Application log filename not as expected")
	assert.Equal(t, ep, *c.Vault.Config.ReSTClientConfig.EndPoint, "Endpoint on vault HTTP client not as expected")
	assert.Equal(t, certPath, *c.Vault.Config.ReSTClientConfig.TrustCACert, "Trust CA cert on vault client not as expected")
	assert.Equal(t, "/testsecret/", c.Vault.Config.SecretsPath, "Secrets path not as expected")
	assert.Equal(t, f.Name(), c.Vault.Credentials.UserIDFile, "UserID file not as expected")
	assert.Equal(t, userid, c.Vault.Credentials.UserID, "UserID not as expected")
	assert.Equal(t, "0f9ef666-cdd9-4176-8c69-2d456be86ac0", c.Vault.Credentials.AppID, "AppID not as expected")
}

func GenerateSelfSignedTLSKeyPairFiles(t *testing.T) (string, string, []byte, *rsa.PrivateKey) {
	derBytes, priv := GenerateSelfSignedTLSKeyPairData(t)
	certOut, _ := ioutil.TempFile(os.TempDir(), "testCert")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, _ := ioutil.TempFile(os.TempDir(), "testKey")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	return certOut.Name(), keyOut.Name(), derBytes, priv
}

func GenerateSelfSignedTLSKeyPairData(t *testing.T) ([]byte, *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 2 * 365 * 24)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "testhost.example.com")
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Errorf("Error creating certifcate for testing: %v", err)
	}
	return derBytes, priv
}
