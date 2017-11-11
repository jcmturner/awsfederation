package httphandling

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jcmturner/awsfederation/config"
	"gopkg.in/jcmturner/goidentity.v1"
	"net/http"
	"net/http/httptest"
	"testing"
	"github.com/stretchr/testify/assert"
	"strings"
)

func TestAccessLogger(t *testing.T) {
	// Simple inner handler func
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		return
	})

	// Set the config to have a byte buffer for the access encoder
	c, _ := config.Mock()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	c.SetAccessEncoder(enc)

	// Form the request
	request, err := http.NewRequest("GET", "/url?query=string", nil)
	if err != nil {
		t.Fatalf("error building request: %v", err)
	}
	request.Host = "shost"
	request.RemoteAddr = "1.2.3.4"
	user := goidentity.NewUser("jcmturner")
	user.SetDomain("domainName")
	ctx := context.WithValue(request.Context(), goidentity.CTXKey, user)

	// Create accessLogger handler and send request
	response := httptest.NewRecorder()
	handler := accessLogger(inner, c)
	handler.ServeHTTP(response, request.WithContext(ctx))

	assert.True(t, strings.HasPrefix(b.String(), `{"SourceIP":"1.2.3.4","Username":"jcmturner","UserRealm":"domainName","StatusCode":204,"Method":"GET","ServerHost":"shost","Path":"/url","QueryString":"query=string","Time":"`))

	j := json.NewDecoder(&b)
	var l AccessLog
	err = j.Decode(&l)
	if err != nil {
		t.Errorf("could not decode access log into JSON object: %v", err)
	}
	assert.NotZero(t, l.Time, "Time in access log is not set")
	assert.NotZero(t, l.Duration, "Duration of request is zero")
}
