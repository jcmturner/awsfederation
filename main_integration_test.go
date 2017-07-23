package awsfederation

import (
	"crypto/x509"
	"fmt"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/gotestingtools/testingTLS"
	"github.com/jcmturner/vaultmock"
	"io/ioutil"
	"os"
	"testing"
)

const (
	TestConfigJSON = `
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

	}
}
`
)

func TestRun(t *testing.T) {
	certPath, keyPath, certBytes, _ := testingTLS.GenerateSelfSignedTLSKeyPairFiles(t)
	//Have to add test cert into a certPool to compare in the assertion as this is all we can get back from the TLSClientConfig of the http.Client and certPool has no public mechanism to extract certs from it
	cert, _ := x509.ParseCertificate(certBytes)
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	s, addr, vCertPool, test_app_id, test_user_id := vaultmock.RunMockVault(t)
	defer s.Close()

	//Create temp userid file
	f, _ := ioutil.TempFile(os.TempDir(), "userid")
	defer os.Remove(f.Name())
	u := fmt.Sprintf(`{
	"UserId": "%s"
	}`, test_user_id)
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

	completeJson := fmt.Sprintf(TestConfigJSON, ls, certPath, keyPath, auditLog.Name(), appLog.Name(), accessLog.Name(), "/testsecret/", ep, certPath, "0f9ef666-cdd9-4176-8c69-2d456be86ac0", "09f28d61-67c0-4587-82f6-e2df56a1b075", f.Name())

	testConfigFile, _ := ioutil.TempFile(os.TempDir(), "config")
	defer os.Remove(testConfigFile.Name())
	testConfigFile.WriteString(completeJson)
	testConfigFile.Close()

	var a app
	a.initialize()
}
