package httphandling

import (
	"context"
	"encoding/base64"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/config"
	"github.com/stretchr/testify/assert"
	goidentity "gopkg.in/jcmturner/goidentity.v1"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"sync"
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
	assert.Equal(t, "LDAP Basic", l.Mechanism(), "Mechanism string not as expected")
}

func TestStaticAuthenticator(t *testing.T) {
	var s StaticAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "StaticAuthenticator does not implement the goidentity.Authenticator interface")
	assert.Equal(t, "Static Basic", s.Mechanism(), "Mechanism string not as expected")
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

func TestAuthnHandlerAndSession(t *testing.T) {
	// Simple inner handler func
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		return
	})
	c, _ := config.Mock()
	rt := mux.NewRouter().StrictSlash(true)
	rt.Methods("GET").
		Path("/").
		Name("TestAuthn").
		Handler(AuthnHandler(inner, c))
	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("error building request: %v", err)
	}
	response := httptest.NewRecorder()
	// Check call needs authentication
	rt.ServeHTTP(response, request)
	assert.Equal(t, http.StatusUnauthorized, response.Code, "Expected unauthorized error")
	// Now authenticated (using testing static auth)
	response = httptest.NewRecorder()
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser@TESTING:"+config.MockStaticSecret)))
	rt.ServeHTTP(response, request)
	assert.Equal(t, http.StatusNoContent, response.Code, "Expected %d", http.StatusNoContent)

	resp := http.Response{Header: response.Header()}
	cookies := resp.Cookies()
	var cookieFound bool
	requestWithCookie, _ := http.NewRequest("GET", "/", nil)
	for _, cookie := range cookies {
		if cookie.Name == sessionCookieName {
			cookieFound = true
			assert.True(t, cookie.HttpOnly, "Cookie not set with HttpOnly")
			assert.True(t, cookie.Secure, "Cookie not set with secure attribute")
			assert.NotZero(t, cookie.Value, "Value not set in cookie")
			assert.True(t, cookie.Expires.After(time.Now().UTC()), "Cookie expires not set as expected")
			assert.True(t, cookie.Expires.Before(time.Now().UTC().Add(time.Minute*time.Duration(c.Server.Authentication.SessionDuration))), "Cookie expires not set as expected")
			assert.False(t, cookie.Expires.After(time.Now().UTC().Add(time.Minute*time.Duration(c.Server.Authentication.SessionDuration+1))), "Cookie expires not set as expected")
		}
		requestWithCookie.AddCookie(cookie)
	}
	assert.True(t, cookieFound, "Session cookie not found in response.")
	response = httptest.NewRecorder()
	rt.ServeHTTP(response, requestWithCookie)
	assert.Equal(t, http.StatusNoContent, response.Code, "Expected %d when using cookie", http.StatusNoContent)

	// Concurrency test
	var wg sync.WaitGroup
	noReq := 10
	wg.Add(noReq)
	for i := 0; i < noReq; i++ {
		go func(){
			defer wg.Done()
			response := httptest.NewRecorder()
			rt.ServeHTTP(response, requestWithCookie)
			assert.Equal(t, http.StatusNoContent, response.Code, "Expected %d when using cookie", http.StatusNoContent)
		}()
	}
	wg.Wait()
}
