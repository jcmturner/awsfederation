package federationuser

import (
	"database/sql"
	"encoding/json"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/gotestingtools/testingTLS"
	"github.com/jcmturner/vaultmock"
	"github.com/stretchr/testify/assert"
	"gopkg.in/DATA-DOG/go-sqlmock.v1"
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
}`
	testFedUserJSON1 = `{
	"Name": "FedUser1",
	"Arn": "arn:aws:iam::123456789012:user",
	"Credentials": {
		"AccessKeyId": "ASIAJEXAMPLEXEG2JICEA",
		"SecretAccessKey": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
		"SessionToken": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
		"Expiration": "2016-03-15T00:05:07Z"
	},
	"TTL": 60,
	"MFASerialNumber": "arn:aws:iam::123456789012:mfa/test",
	"MFASecret" "V2NFI2CRKFCMZJD232ONV5OLVPN5H3ZO2553QHFPXJK4BJN4X3JBYEQ6DJSBXE7H"
}`
	Test_SecretsPath            = "/secret/awskeys/"
	testFedUserARN1             = "arn:aws:iam::123456789012:user/test1"
	testFedUserName1            = "FedUser1"
	testFedUserAccessKeyId1     = "ASIAJEXAMPLEXEG2JICEA"
	testFedUserSecretAccessKey1 = "9drTJvcXLB89EXAMPLELB8923FB892xMFI"
	testFedUserSessionToken1    = "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	testFedUserExpiration1      = "2016-03-15T00:05:07Z"
	testFedUserTTL1             = 60
	testFedUserMFASerialNumber1 = "arn:aws:iam::123456789012:mfa/test"
	testFedUserMFASecret1       = "V2NFI2CRKFCMZJD232ONV5OLVPN5H3ZO2553QHFPXJK4BJN4X3JBYEQ6DJSBXE7H"
	redacted                    = "REDACTED"
)

func testEnv(t *testing.T) (*config.Config, *sql.DB, sqlmock.Sqlmock, map[int]*sqlmock.ExpectedPrepare, *database.StmtMap, *httptest.Server) {
	// Database mock and prepare statements
	db, mock, ep, stmtMap := database.Mock(t)

	// Start a mock vault process
	s, addr, _, cert, appID, userID := vaultmock.RunMockVault(t)
	vCertFile := testingTLS.WriteCertToFile(t, cert)
	defer os.Remove(vCertFile.Name())

	// Create a cert for the server
	// TODO the testingTLS method should also return the cert as a cert object we can return to trust it.
	certPath, keyPath, _, _ := testingTLS.GenerateSelfSignedTLSKeyPairFiles(t)
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	c, _ := config.Mock()
	c.SetTLS(
		config.TLS{
			Enabled:         true,
			CertificateFile: certPath,
			KeyFile:         keyPath,
		})
	c.SetVault(addr, vCertFile.Name(), appID, userID, Test_SecretsPath)

	// Form the configuration JSON text and write to a file
	//completeJson := fmt.Sprintf(TestConfigJSON, "127.0.0.1:9443", certPath, keyPath, Test_SecretsPath, addr, vCertFile.Name(), test_app_id, f.Name())
	//t.Logf("Config:\n %s\n", completeJson)

	//c, err := config.Parse([]byte(completeJson))
	//if err != nil {
	//	t.Fatalf("Error parsing configuration: %v", err)
	//}

	return c, db, mock, ep, stmtMap, s
}

func TestFederationUser_StoreLoadDelete(t *testing.T) {
	c, db, _, ep, stmtMap, s := testEnv(t)
	defer s.Close()
	defer db.Close()
	fu, err := NewFederationUser(c, testFedUserARN1)
	if err != nil {
		t.Fatalf("Error creating FederationUser: %v", err)
	}
	fu.SetName(testFedUserName1)
	expTime, _ := time.Parse(time.RFC3339, testFedUserExpiration1)
	fu.SetCredentials(testFedUserAccessKeyId1,
		testFedUserSecretAccessKey1,
		testFedUserSessionToken1,
		expTime,
		int64(testFedUserTTL1),
		testFedUserMFASerialNumber1,
		testFedUserMFASecret1)

	// Set the expected database call
	ep[database.StmtKeyFedUserInsert].ExpectExec().WithArgs(testFedUserARN1).WillReturnResult(sqlmock.NewResult(0, 1))
	err = fu.Store(*stmtMap)
	if err != nil {
		t.Fatalf("Error storing Federation user: %v", err)
	}

	m, err := fu.Provider.VaultClient.Read(testFedUserARN1)
	assert.Equal(t, testFedUserName1, m["Name"].(string), "Stored name not as expected")
	assert.Equal(t, testFedUserAccessKeyId1, m["AccessKeyID"].(string), "Stored AccessKeyID not as expected")
	assert.Equal(t, testFedUserSecretAccessKey1, m["SecretAccessKey"].(string), "Stored SecretAccessKey not as expected")
	assert.Equal(t, testFedUserSessionToken1, m["SessionToken"].(string), "Stored SessionToken not as expected")
	assert.Equal(t, testFedUserMFASerialNumber1, m["MFASerialNumber"].(string), "Stored MFA serial number not as expected")
	assert.Equal(t, testFedUserMFASecret1, m["MFASecret"].(string), "Stored MFA secret not as expected")
	assert.Equal(t, testFedUserExpiration1, m["Expiration"].(string), "Stored expiration not as expected")
	ttl, _ := m["TTL"].(json.Number).Int64()
	assert.Equal(t, int64(testFedUserTTL1), ttl, "Stored TTL not as expected")

	fuLoad, err := NewFederationUser(c, testFedUserARN1)
	if err != nil {
		t.Fatalf("Error creating FederationUser for loading into: %v", err)
	}
	err = fuLoad.Load()
	if err != nil {
		t.Fatalf("Error loading federation user: %v", err)
	}
	assert.Equal(t, testFedUserARN1, fuLoad.ARNString, "ARN string not as expected after load")
	assert.Equal(t, testFedUserARN1, fuLoad.ARN.String(), "ARN not as expected after load")
	assert.Equal(t, testFedUserName1, fuLoad.Name, "Name not as expected after load")
	assert.Equal(t, expTime, fuLoad.Credentials.Expiration, "Credential expiration not as expected after load")
	assert.Equal(t, redacted, fuLoad.MFASecret, "MFA secret not as expected after load")
	assert.Equal(t, testFedUserMFASerialNumber1, fuLoad.MFASerialNumber, "MFA serial number not as expected after load")
	assert.Equal(t, int64(testFedUserTTL1), fuLoad.TTL, "TTL not as expected after load")
	assert.Equal(t, testFedUserAccessKeyId1, fuLoad.Credentials.AccessKeyID, "AccessKeyID not as expected after load")
	assert.Equal(t, redacted, fuLoad.Credentials.SecretAccessKey, "SecretAccessKey not as expected after load")
	assert.Equal(t, redacted, fuLoad.Credentials.SessionToken, "SessionToken not as expected after load")

	//Store the same again
	// Set the expected database call
	ep[database.StmtKeyFedUserInsert].ExpectExec().WithArgs(testFedUserARN1).WillReturnResult(sqlmock.NewResult(0, 0))
	err = fu.Store(*stmtMap)
	if err != nil {
		t.Fatalf("Error storing Federation user 2nd time: %v", err)
	}

	ep[database.StmtKeyFedUserDelete].ExpectExec().WithArgs(testFedUserARN1).WillReturnResult(sqlmock.NewResult(0, 1))
	err = fuLoad.Delete(*stmtMap)
	if err != nil {
		t.Fatalf("Error deleting federation user: %v", err)
	}

}
