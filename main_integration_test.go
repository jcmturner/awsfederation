package awsfederation

import (
	"fmt"
	"github.com/jcmturner/gotestingtools/testingTLS"
	"github.com/jcmturner/vaultmock"
	"io/ioutil"
	"os"
	"testing"
	"net"
	"github.com/jcmturner/restclient"
	"crypto/x509"
	"github.com/jcmturner/vaultclient"
	"github.com/jcmturner/awsvaultcredsprovider"
	"time"
	"github.com/jcmturner/awsfederation/httphandling"
	"github.com/jcmturner/awsfederation/federationuser"
	"net/http"
	"net/http/httptest"
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
			"UserIDFile": "%s"
		}

	}
}
`

	Test_SecretAccessKey = "9drTJvcXLB89EXAMPLELB8923FB892xMFI"
	Test_SessionToken    = "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	Test_Expiration      = "2016-03-15T00:05:07Z"
	Test_AccessKeyId     = "ASIAJEXAMPLEXEG2JICEA"
	Test_SecretsPath     = "/secret/awskeys/"
	Test_Arn             = "arn:aws:iam::123456789012:user/test"
)

func TestRun(t *testing.T) {
	a, v := initServer(t)
	defer v.Close()
	a.run()
	c := restclient.NewConfig().WithEndPoint("https://"+a.Config.Server.Socket).WithCAFilePath(a.Config.Server.TLS.CertificateFile)
	path := fmt.Sprintf("/" + httphandling.APIVersion +"/federationuser/"+Test_Arn)
	t.Logf("Testing Path: %v\n", path)
	fu := federationuser.FederationUser{}
	o := restclient.NewGetOperation().WithPath(path).WithResponseTarget(&fu)
	req, err := restclient.BuildRequest(c, o)
	if err != nil {
		t.Fatalf("Error building request: %v\n", err)
	}
	httpCode, err := restclient.Send(req)
	if err != nil {
		t.Fatalf("Error sending request: %v\n", err)
	}
	if *httpCode != http.StatusOK {
		t.Fatalf("Did not get an HTTP 200 code, got %v", *httpCode)
	}
	t.Logf("Response: %+v\n", fu)
}

func initServer(t *testing.T) (*app, *httptest.Server) {
	// Start a mock vault process
	s, addr, vCertPool, test_app_id, test_user_id := vaultmock.RunMockVault(t)
	vCertFile := testingTLS.WriteCertPoolToFile(t, *vCertPool)

	// Populate the vault
	populateVault(t, addr, vCertPool, test_app_id, test_user_id)

	// Create a cert for the server
	certPath, keyPath, _, _ := testingTLS.GenerateSelfSignedTLSKeyPairFiles(t)

	// Create temp userid file
	f, _ := ioutil.TempFile(os.TempDir(), "userid")
	defer os.Remove(f.Name())
	u := fmt.Sprintf(`{
	"UserId": "%s"
	}`, test_user_id)
	f.WriteString(u)
	f.Close()

	// Create log files
	auditLog, _ := ioutil.TempFile(os.TempDir(), "mockAuditlogfile")
	defer os.Remove(auditLog.Name())
	auditLog.Close()
	appLog, _ := ioutil.TempFile(os.TempDir(), "mockApplogfile")
	defer os.Remove(appLog.Name())
	appLog.Close()
	accessLog, _ := ioutil.TempFile(os.TempDir(), "mockAccesslogfile")
	defer os.Remove(accessLog.Name())
	accessLog.Close()

	// Get a listening socket for the server
	ls, _ := net.Listen("tcp", "127.0.0.1:0")
	ls.Close()
	t.Log(ls.Addr().String())

	// Form the configuration JSON text and write to a file
	completeJson := fmt.Sprintf(TestConfigJSON, "127.0.0.1:9443", certPath, keyPath, auditLog.Name(), appLog.Name(), accessLog.Name(), Test_SecretsPath, addr, vCertFile.Name(), test_app_id, f.Name())
	testConfigFile, _ := ioutil.TempFile(os.TempDir(), "config")
	defer os.Remove(testConfigFile.Name())
	testConfigFile.WriteString(completeJson)
	testConfigFile.Close()

	// Initialise and run the app
	var a app
	a.initialize(testConfigFile.Name())
	return &a, s
}

func populateVault(t *testing.T, addr string, certPool *x509.CertPool, test_app_id, test_user_id string) {
	c := restclient.NewConfig().WithEndPoint(addr).WithCACertPool(certPool)
	vconf := vaultclient.Config{
		SecretsPath:      Test_SecretsPath,
		ReSTClientConfig: *c,
	}
	vcreds := vaultclient.Credentials{
		UserID: test_user_id,
		AppID:  test_app_id,
	}
	p, err := awsvaultcredsprovider.NewVaultCredsProvider(Test_Arn, vconf, vcreds)
	if err != nil {
		t.Fatalf("Error creating VaultCredsProvider: %v", err)
	}

	xt, err := time.Parse(time.RFC3339, Test_Expiration)
	if err != nil {
		t.Logf("Error parsing test expiry time: %v", err)
	}
	p.SetAccessKey(Test_AccessKeyId).SetExpiration(xt).SetSecretAccessKey(Test_SecretAccessKey).SetSessionToken(Test_SessionToken)

	// Store
	err = p.Store()
	if err != nil {
		t.Fatalf("Failed to store AWS credential: %v", err)
	}
}
