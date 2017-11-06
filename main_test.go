package main

import (
	"crypto/x509"
	"fmt"
	"github.com/jcmturner/awsfederation/app"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsvaultcredsprovider"
	"github.com/jcmturner/gotestingtools/testingTLS"
	"github.com/jcmturner/restclient"
	"github.com/jcmturner/vaultclient"
	"github.com/jcmturner/vaultmock"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"testing"
	"time"
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

	},
	"Database": {
		"ConnectionString": "%s",
		"CredentialsVaultPath": "%s"
	}
}
`
	TestVaultRoot        = "/secret/"
	Test_DB_Conn         = "${username}:${password}@tcp(127.0.0.1:3306)/awsfederation"
	Test_DB_Creds_Path   = "dbcreds"
	Test_Arn_Stub        = "arn:aws:iam::123456789012:user"
	Test_FedName         = "TestFedUser"
	Test_Arn             = "arn:aws:iam::123456789012:user/test"
	Test_SecretAccessKey = "9drTJvcXLB89EXAMPLELB8923FB892xMFI"
	Test_SessionToken    = "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	Test_Expiration      = "2016-03-15T00:05:07Z"
	Test_AccessKeyId     = "ASIAJEXAMPLEXEG2JICEA"

	Test_Arn_Stub2        = "arn:aws:iam::223456789012:user"
	Test_FedName2         = "TestFedUser2"
	Test_Arn2             = "arn:aws:iam::223456789012:user/test2"
	Test_SecretAccessKey2 = "9dje5ucXLB89EXAMPLELB8923FB892xMFI"
	Test_SessionToken2    = "BQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	Test_Expiration2      = "2017-08-15T03:05:07Z"
	Test_AccessKeyId2     = "ASIAJEXAMPLEXEG2JICEB"
	Test_MFASerial2       = "arn:aws:iam::223456789012:mfa/test2"
	Test_MFASecret2       = "V2NFI2CRKFCMZJD232ONV5OLVPN5H3ZO2553QHFPXJK4BJN4X3JBYEQ6DJSBXE7H"

	MessageTemplateJSON = "{\"Message\":\"%s\",\"HTTPCode\":%d,\"ApplicationCode\":%d}"
)

//
//func TestFederationUserRestAPI(t *testing.T) {
//	a, v := initServer(t)
//	defer v.Close()
//
//	var tests = []struct {
//		Method         string
//		Path           string
//		PostPayload    string
//		HttpCode       int
//		ResponseString string
//	}{
//		{"GET", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn, "", http.StatusOK, "{\"Name\":\"\",\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}"},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser", "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn + "\"]}"},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn_Stub, "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn + "\"]}"},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser/arn:aws:iam::123456789012:user/notexist", "", http.StatusNotFound, fmt.Sprintf(MessageTemplateJSON, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
//		{"POST", "/" + httphandling.APIVersion + "/federationuser", "{\"Name\":\"" + Test_FedName + "\",\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}", http.StatusConflict, fmt.Sprintf(MessageTemplateJSON, "Federation user already exists.", http.StatusConflict, appcodes.FederationUserAlreadyExists)},
//		{"POST", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn, "{\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"" + Test_SecretAccessKey2 + "\",\"SessionToken\":\"" + Test_SessionToken2 + "\",\"Expiration\":\"" + Test_Expiration2 + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":12,\"MFASerialNumber\":\"" + Test_MFASerial2 + "\",\"MFASecret\":\"" + Test_MFASecret2 + "\"}", http.StatusMethodNotAllowed, fmt.Sprintf(MessageTemplateJSON, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
//		{"POST", "/" + httphandling.APIVersion + "/federationuser", "{\"Name\":\"" + Test_FedName2 + "\",\"Arn\":\"" + Test_Arn2 + "\",\"Credentials\":{\"SecretAccessKey\":\"" + Test_SecretAccessKey2 + "\",\"SessionToken\":\"" + Test_SessionToken2 + "\",\"Expiration\":\"" + Test_Expiration2 + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":12,\"MFASerialNumber\":\"" + Test_MFASerial2 + "\",\"MFASecret\":\"" + Test_MFASecret2 + "\"}", http.StatusOK, fmt.Sprintf(MessageTemplateJSON, "Federation user "+Test_Arn2+" created.", http.StatusOK, appcodes.Info)},
//		{"DELETE", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn2, "", http.StatusOK, fmt.Sprintf(MessageTemplateJSON, "Federation user "+Test_Arn2+" deleted.", http.StatusNotFound, appcodes.Info)},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn2, "", http.StatusNotFound, fmt.Sprintf(MessageTemplateJSON, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
//		{"POST", "/" + httphandling.APIVersion + "/federationuser", "{\"Name\":\"" + Test_FedName2 + "\",\"Arn\":\"" + Test_Arn2 + "\",\"Credentials\":{\"SecretAccessKey\":\"" + Test_SecretAccessKey2 + "\",\"SessionToken\":\"" + Test_SessionToken2 + "\",\"Expiration\":\"" + Test_Expiration2 + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":12,\"MFASerialNumber\":\"" + Test_MFASerial2 + "\",\"MFASecret\":\"" + Test_MFASecret2 + "\"}", http.StatusOK, fmt.Sprintf(MessageTemplateJSON, "Federation user "+Test_Arn2+" created.", http.StatusOK, appcodes.Info)},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn2, "", http.StatusOK, "{\"Arn\":\"" + Test_Arn2 + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration2 + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":12,\"MFASerialNumber\":\"" + Test_MFASerial2 + "\",\"MFASecret\":\"REDACTED\"}"},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser", "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn + "\",\"" + Test_Arn2 + "\"]}"},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn_Stub, "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn + "\"]}"},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn_Stub2, "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn2 + "\"]}"},
//		{"PUT", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn_Stub + "/blah", "{\"Name\":\"" + Test_FedName + "\",\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}", http.StatusNotFound, fmt.Sprintf(MessageTemplateJSON, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
//		{"PUT", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn, "{\"Name\":\"" + Test_FedName + "\",\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}", http.StatusOK, fmt.Sprintf(MessageTemplateJSON, "Federation user "+Test_Arn+" updated.", http.StatusNotFound, appcodes.Info)},
//		{"GET", "/" + httphandling.APIVersion + "/federationuser/" + Test_Arn, "", http.StatusOK, "{\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}"},
//	}
//	for _, test := range tests {
//		t.Logf("Test %s %s\n", test.Method, test.Path)
//		request, _ := http.NewRequest(test.Method, test.Path, strings.NewReader(test.PostPayload))
//		response := httptest.NewRecorder()
//		a.Router.ServeHTTP(response, request)
//		assert.Equal(t, test.HttpCode, response.Code, fmt.Sprintf("Expected HTTP code: %d got: %d (%s %s)", test.HttpCode, response.Code, test.Method, test.Path))
//		assert.Equal(t, test.ResponseString, response.Body.String(), fmt.Sprintf("Response not as expected (%s %s)", test.Method, test.Path))
//	}
//	fu, err := federationuser.NewFederationUser(a.Config, Test_Arn2)
//	if err != nil {
//		t.Fatalf("Error testing vault content: %v", err)
//	}
//	if err := fu.Provider.Read(); err != nil {
//		t.Fatalf("Error testing vault content: %v", err)
//	}
//	//Test backend storage directly
//	assert.Equal(t, Test_Arn2, fu.ARNString, "ARN not stored as expected")
//	assert.Equal(t, Test_AccessKeyId2, fu.Provider.Credential.AccessKeyId, "ARN not stored as expected")
//	assert.Equal(t, Test_SessionToken2, fu.Provider.Credential.GetSessionToken(), "SessionToken not stored as expected")
//	assert.Equal(t, Test_SecretAccessKey2, fu.Provider.Credential.GetSecretAccessKey(), "SecretAccessKey not stored as expected")
//	et, _ := time.Parse(time.RFC3339, Test_Expiration2)
//	assert.Equal(t, et, fu.Provider.Credential.Expiration, "Expiration not stored as expected")
//	assert.Equal(t, Test_MFASerial2, fu.Provider.Credential.MFASerialNumber, "MFA serial not stored as expected")
//	assert.Equal(t, Test_MFASecret2, fu.Provider.Credential.GetMFASecret(), "MFA secret not stored as expected")
//
//}

func initServer(t *testing.T) (*app.App, *httptest.Server) {
	// Start a mock vault process
	s, addr, vCertPool, cert, test_app_id, test_user_id := vaultmock.RunMockVault(t)
	vCertFile := testingTLS.WriteCertToFile(t, cert)

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
	//ls, _ := net.Listen("tcp", "127.0.0.1:0")
	//ls.Close()
	//ls.Addr().String())

	// Form the configuration JSON text and write to a file
	completeJson := fmt.Sprintf(TestConfigJSON, "127.0.0.1:9443", certPath, keyPath, auditLog.Name(), appLog.Name(), accessLog.Name(), TestVaultRoot, addr, vCertFile.Name(), test_app_id, f.Name(), Test_DB_Conn, Test_DB_Creds_Path)
	testConfigFile, _ := ioutil.TempFile(os.TempDir(), "config")
	defer os.Remove(testConfigFile.Name())
	testConfigFile.WriteString(completeJson)
	testConfigFile.Close()

	// Initialise and run the app
	var a app.App
	// Load configuration
	c, _ := config.Load(testConfigFile.Name())
	a.Initialize(c)
	return &a, s
}

func populateVault(t *testing.T, addr string, certPool *x509.CertPool, test_app_id, test_user_id string) {
	c := restclient.NewConfig().WithEndPoint(addr).WithCACertPool(certPool)
	vconf := vaultclient.Config{
		SecretsPath:      TestVaultRoot,
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

	cl, err := vaultclient.NewClient(&vconf, &vcreds)
	dbs := map[string]interface{}{
		"username": "dbusername",
		"password": "dbpassword",
	}
	cl.Write(Test_DB_Creds_Path, dbs)
}
