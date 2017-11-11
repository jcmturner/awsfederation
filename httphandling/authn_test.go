package httphandling

import (
	"context"
	"github.com/stretchr/testify/assert"
	goidentity "gopkg.in/jcmturner/goidentity.v1"
	"testing"
)

func TestGetIdentity(t *testing.T) {
	user := goidentity.NewUser("jcmturner")
	ctx := context.Background()
	ctx = context.WithValue(ctx, goidentity.CTXKey, user)

	id, err := GetIdentity(ctx)
	if err != nil {
		t.Logf("error from GetIdentity: %v", err)
	}
	assert.Equal(t, "jcmturner", id.UserName(), "username in returned identity not as expected")
	assert.Equal(t, &user, id, "identity in context and identity returned are not the same")
}

func TestLDAPBasicAuthenticator(t *testing.T) {
	var l LDAPBasicAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, l, "LDAPBasicAuthenticator does not implement the goidentity.Authenticator interface")
}

func TestStaticAuthenticator(t *testing.T) {
	var s StaticAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "LDAPBasicAuthenticator does not implement the goidentity.Authenticator interface")
}

func TestParseBasicHeaderValue(t *testing.T) {
	var tests = []struct {
		testname  string
		valid     bool
		base64Str string
		domain    string
		username  string
		password  string
	}{
		{"valid-backslash", true, "ZG9tYWluTmFtZVxqY210dXJuZXI6bXlwYXNzd29yZA==", "domainName", "jcmturner", "mypassword"},
		{"valid-forwardslash", true, "ZG9tYWluTmFtZS9qY210dXJuZXI6bXlwYXNzd29yZA==", "domainName", "jcmturner", "mypassword"},
		{"valid-atsymbol", true, "amNtdHVybmVyQGRvbWFpbk5hbWU6bXlwYXNzd29yZA==", "domainName", "jcmturner", "mypassword"},
		{"valid-nodomain", true, "amNtdHVybmVyOm15cGFzc3dvcmQ=", "", "jcmturner", "mypassword"},
		{"invalid-nocolon", false, "amNtdHVybmVybXlwYXNzd29yZA==", "", "jcmturner", "mypassword"},
	}
	for _, test := range tests {
		d, u, p, err := ParseBasicHeaderValue(test.base64Str)
		if test.valid {
			assert.Nil(t, err, "error from parsing not nil for test %s: %v", test.testname, err)
			assert.Equal(t, test.domain, d, "domain not as expected: %s", test.testname)
			assert.Equal(t, test.username, u, "username not as expected: %s", test.testname)
			assert.Equal(t, test.password, p, "domain not as expected: %s", test.testname)
		} else {
			assert.NotNil(t, err, "invalid header did not generate error")
		}
	}
}
