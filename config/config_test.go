package config

import (
	"crypto/x509"
	"fmt"
	"github.com/jcmturner/gotestingtools/testingTLS"
	"github.com/jcmturner/restclient"
	"github.com/jcmturner/vaultclient"
	"github.com/jcmturner/vaultmock"
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
		"Authentication": {
			"Kerberos": {
				"Enabled": false,
				"KeytabVaultPath": "-",
				"ServiceAccount": ""
			},
			"Basic": {
				"Enabled": false,
				"Realm": "AWSFederationTest",
				"Protocol": "Kerberos",
				"Kerberos": {
					"KRB5ConfPath": "-",
					"KeytabVaultPath": "-",
					"ServiceAccount": "",
					"SPN": "aws.test.gokrb5"
				},
				"LDAP": {
					"EndPoint": "10.80.389.1:389",
					"BaseDN": "dc=test,dc=gokrb5",
					"UsernameAttribute": "uid",
					"UserObjectClass": "inetOrgPerson",
					"DisplayNameAttribute": "cn",
					"MembershipAttribute": "memberof",
					"BindUserDN": "uid=ldapbind,ou=users,dc=test,dc=gokrb5",
					"BindUserPasswordVaultPath": "-",
					"TLSEnabled": false,
					"TrustedCAPath": "-"
				}
			}
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
	TestServerSocket                  = "127.0.0.1:9443"
	TestServerTLSEnabled              = true
	TestVaultRoot                     = "/secret/"
	TestKerbAuthnEnabled              = true
	TestKeytabVaultPath               = "keytab"
	TestKeytabHex                     = "05020000003b0001000b544553542e474f4b524235000974657374757365723100000001592d16240100110010698c4df8e9f60e7eea5a21bf4526ad25000000010000004b0001000b544553542e474f4b524235000974657374757365723100000001592d16240100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000010000003b0001000b544553542e474f4b524235000974657374757365723100000001592d16240200110010698c4df8e9f60e7eea5a21bf4526ad25000000020000004b0001000b544553542e474f4b524235000974657374757365723100000001592d16240200120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000020000003b0001000b544553542e474f4b524235000974657374757365723100000001592d162401001300102eb8501967a7886e1f0c63ac9be8c4a0000000010000003b0001000b544553542e474f4b524235000974657374757365723100000001592d162402001300102eb8501967a7886e1f0c63ac9be8c4a0000000020000004b0001000b544553542e474f4b524235000974657374757365723100000001592d162401001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee000000010000004b0001000b544553542e474f4b524235000974657374757365723100000001592d162402001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee00000002000000430001000b544553542e474f4b524235000974657374757365723100000001592d162401001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e300000001000000430001000b544553542e474f4b524235000974657374757365723100000001592d162402001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e300000002"
	TestBasicAuthnEnabled             = true
	TestBasicRealm                    = "AWSFederationTest"
	TestBasicProtocol                 = "Kerberos"
	TestSPN                           = "aws.fed.test"
	TestLDAPEndpoint                  = "10.80.389.1:389"
	TestLDAPBaseDN                    = "dc=fed,dc=test"
	TestUsernameAttribute             = "uid"
	TestLDAPUserObjectClass           = ""
	TestLDAPDisplayNameAttribute      = "cn"
	TestLDAPMembershipAttribute       = "memberof"
	TestLDAPBindUserDN                = "uid=binduser,ou=users,dc=fed,dc=test"
	TestLDAPBindUserPasswordVaultPath = "bindpassword"
	TestLDAPTLSEnabled                = true
	TestLDAPTrustedCAPath             = "/some/path/to/cert.pem"
	TestDBConn                        = "${username}:${password}@tcp(127.0.0.1:3306)/awsfederation"
	TestDBCredsPath                   = "dbcreds"
	TestKrb5Conf                      = `[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96

[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
 `
)

func TestLoad(t *testing.T) {
	//Start up a mock vault
	s, addr, vcertPool, vcert, app_id, userid := vaultmock.RunMockVault(t)
	defer s.Close()
	vcertFile := testingTLS.WriteCertToFile(t, vcert)
	populateVault(t, addr, vcertPool, app_id, userid)

	certPath, keyPath, certBytes, _ := testingTLS.GenerateSelfSignedTLSKeyPairFiles(t)
	//Have to add test cert into a certPool to compare in the assertion as this is all we can get back from the TLSClientConfig of the http.Client and certPool has no public mechanism to extract certs from it
	cert, _ := x509.ParseCertificate(certBytes)
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	//Create temp userid file
	f, _ := ioutil.TempFile(os.TempDir(), "userid")
	defer os.Remove(f.Name())
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

	// Create krb5.conf file
	krbconf, _ := ioutil.TempFile(os.TempDir(), "krb5conf")
	f.WriteString(TestKrb5Conf)
	krbconf.Close()

	completeJson := fmt.Sprintf(TemplateJSON,
		// Server level config
		TestServerSocket, TestServerTLSEnabled, certPath, keyPath,
		// Kerberos SPNEGO config
		TestKerbAuthnEnabled, TestKeytabVaultPath, "",
		// Basic auth config
		TestBasicAuthnEnabled, TestBasicRealm, TestBasicProtocol,
		// Kerberos basic auth config
		krbconf.Name(), TestKeytabVaultPath, "", TestSPN,
		// LDAP basic auth config
		TestLDAPEndpoint, TestLDAPBaseDN, TestUsernameAttribute, TestLDAPUserObjectClass, TestLDAPDisplayNameAttribute, TestLDAPMembershipAttribute, TestLDAPBindUserDN, TestLDAPBindUserPasswordVaultPath, TestLDAPTLSEnabled, TestLDAPTrustedCAPath,
		// Logging config
		auditLog.Name(), appLog.Name(), accessLog.Name(),
		// Vault config
		TestVaultRoot, addr, vcertFile.Name(), app_id, userid, f.Name(),
		// Database config
		TestDBConn, TestDBCredsPath)

	testConfigFile, _ := ioutil.TempFile(os.TempDir(), "config")
	defer os.Remove(testConfigFile.Name())
	testConfigFile.WriteString(completeJson)
	testConfigFile.Close()
	c, err := Load(testConfigFile.Name())
	if err != nil {
		t.Fatalf("Error loading configuration JSON: %v", err)
	}
	assert.Equal(t, TestServerSocket, c.Server.Socket, "Server socket not as expected")
	assert.Equal(t, true, c.Server.TLS.Enabled, "TLS note enabled")
	assert.Equal(t, certPath, c.Server.TLS.CertificateFile, "Server certificate not as expected")
	assert.Equal(t, keyPath, c.Server.TLS.KeyFile, "Server key file not as expected")
	assert.True(t, c.Server.Authentication.Kerberos.Enabled, "Kerberos authentication should be enabled")
	assert.Equal(t, TestKeytabVaultPath, c.Server.Authentication.Kerberos.KeytabVaultPath, "Kerberos authn keytab vault path not as expected")
	assert.True(t, c.Server.Authentication.Basic.Enabled, "Basic authn not enabled")
	assert.Equal(t, TestBasicRealm, c.Server.Authentication.Basic.Realm, "Basic authn realm not as expected")
	assert.Equal(t, TestBasicProtocol, c.Server.Authentication.Basic.Protocol, "Basic authn protocol not as expected")
	assert.Equal(t, TestSPN, c.Server.Authentication.Basic.Kerberos.SPN, "Kerberos basic authn SPN not as expected")
	assert.Equal(t, TestLDAPEndpoint, c.Server.Authentication.Basic.LDAP.EndPoint, "LDAP endpoint not as expected")
	assert.Equal(t, TestLDAPBaseDN, c.Server.Authentication.Basic.LDAP.BaseDN, "LDAP Base DN not as expected")
	assert.Equal(t, TestUsernameAttribute, c.Server.Authentication.Basic.LDAP.UsernameAttribute, "LDAP UsernameAttribute not as expected")
	assert.Equal(t, TestLDAPUserObjectClass, c.Server.Authentication.Basic.LDAP.UserObjectClass, "LDAP UserObjectClass not as expected")
	assert.Equal(t, TestLDAPDisplayNameAttribute, c.Server.Authentication.Basic.LDAP.DisplayNameAttribute, "LDAP DisplayNameAttribute not as expected")
	assert.Equal(t, TestLDAPMembershipAttribute, c.Server.Authentication.Basic.LDAP.MembershipAttribute, "LDAP MembershipAttribute not as expected")
	assert.Equal(t, TestLDAPBindUserDN, c.Server.Authentication.Basic.LDAP.BindUserDN, "LDAP bind user DN not as expected")
	assert.Equal(t, TestLDAPBindUserPasswordVaultPath, c.Server.Authentication.Basic.LDAP.BindUserPasswordVaultPath, "Bind user password vault path not as expected")
	assert.True(t, c.Server.Authentication.Basic.LDAP.TLSEnabled, "LDAP TLS not enabled")
	assert.Equal(t, TestLDAPTrustedCAPath, c.Server.Authentication.Basic.LDAP.TrustedCAPath, "LDAP connection trusted CA not as expected")
	assert.Equal(t, appLog.Name(), c.Server.Logging.ApplicationFile, "Application log filename not as expected")
	assert.Equal(t, addr, *c.Vault.Config.ReSTClientConfig.EndPoint, "Endpoint on vault HTTP client not as expected")
	assert.Equal(t, vcertFile.Name(), *c.Vault.Config.ReSTClientConfig.TrustCACert, "Trust CA cert on vault client not as expected")
	assert.Equal(t, *vcertPool, *c.Vault.Config.ReSTClientConfig.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs, "CA cert for Vault connection not set on client transport")
	assert.Equal(t, TestVaultRoot, c.Vault.Config.SecretsPath, "Secrets path not as expected")
	assert.Equal(t, f.Name(), c.Vault.Credentials.UserIDFile, "UserID file not as expected")
	assert.Equal(t, userid, c.Vault.Credentials.UserID, "UserID not as expected")
	assert.Equal(t, app_id, c.Vault.Credentials.AppID, "AppID not as expected")
	assert.Equal(t, TestDBConn, c.Database.ConnectionString, "Database connection string not as expected")
	assert.Equal(t, TestDBCredsPath, c.Database.CredentialsVaultPath, "Database credentials path not as expected")
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
	vc, _ := vaultclient.NewClient(&vconf, &vcreds)
	krbkeytab := map[string]interface{}{
		"keytab": TestKeytabHex,
	}
	vc.Write(TestVaultRoot+TestKeytabVaultPath, krbkeytab)
}
