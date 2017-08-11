package config

import (
	"crypto/x509"
	"fmt"
	"github.com/jcmturner/gotestingtools/testingTLS"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
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
			"Application": "%s",
			"Access": "%s"
		}
	},
	"Vault": {
		"Config": {
			"SecretsPath": "%s",
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
	Test_DB_Conn       = "${username}:${password}@tcp(127.0.0.1:3306)/awsfederation"
	Test_DB_Creds_Path = "/secret/dbcreds/"
)

func TestLoad(t *testing.T) {
	certPath, keyPath, certBytes, _ := testingTLS.GenerateSelfSignedTLSKeyPairFiles(t)
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
	accessLog, _ := ioutil.TempFile(os.TempDir(), "mockAccesslogfile")
	defer os.Remove(accessLog.Name())
	accessLog.Close()

	ls := "127.0.0.1:9443"
	ep := "https://127.0.0.1:8200"

	completeJson := fmt.Sprintf(TestJSON, ls, certPath, keyPath, auditLog.Name(), appLog.Name(), accessLog.Name(), "/testsecret/", ep, certPath, "0f9ef666-cdd9-4176-8c69-2d456be86ac0", "09f28d61-67c0-4587-82f6-e2df56a1b075", f.Name(), Test_DB_Conn, Test_DB_Creds_Path)

	testConfigFile, _ := ioutil.TempFile(os.TempDir(), "config")
	defer os.Remove(testConfigFile.Name())
	testConfigFile.WriteString(completeJson)
	testConfigFile.Close()
	c, err := Load(testConfigFile.Name())
	if err != nil {
		t.Fatalf("Error loading configuration JSON: %v", err)
	}
	assert.Equal(t, ls, c.Server.Socket, "Server socket not as expected")
	assert.Equal(t, true, c.Server.TLS.Enabled, "TLS note enabled")
	assert.Equal(t, certPath, c.Server.TLS.CertificateFile, "Server certificate not as expected")
	assert.Equal(t, keyPath, c.Server.TLS.KeyFile, "Server key file not as expected")
	assert.Equal(t, auditLog.Name(), c.Server.Logging.AuditFile, "Audit log filename not as expected")
	assert.Equal(t, appLog.Name(), c.Server.Logging.ApplicationFile, "Application log filename not as expected")
	assert.Equal(t, ep, *c.Vault.Config.ReSTClientConfig.EndPoint, "Endpoint on vault HTTP client not as expected")
	assert.Equal(t, certPath, *c.Vault.Config.ReSTClientConfig.TrustCACert, "Trust CA cert on vault client not as expected")
	assert.Equal(t, *certPool, *c.Vault.Config.ReSTClientConfig.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs, "CA cert for Vault connection not set on client transport")
	assert.Equal(t, "/testsecret/", c.Vault.Config.SecretsPath, "Secrets path not as expected")
	assert.Equal(t, f.Name(), c.Vault.Credentials.UserIDFile, "UserID file not as expected")
	assert.Equal(t, userid, c.Vault.Credentials.UserID, "UserID not as expected")
	assert.Equal(t, "0f9ef666-cdd9-4176-8c69-2d456be86ac0", c.Vault.Credentials.AppID, "AppID not as expected")
	assert.Equal(t, Test_DB_Conn, c.Database.ConnectionString, "Database connection string not as expected")
	assert.Equal(t, Test_DB_Creds_Path, c.Database.CredentialsVaultPath, "Database credentials path not as expected")
}
