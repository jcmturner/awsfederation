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
)

func TestAccessLogger(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		return
	})

	c, _ := config.Mock()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	c.SetAccessEncoder(enc)

	handler := accessLogger(inner, c)

	request, err := http.NewRequest("GET", "/url?query=string", nil)
	if err != nil {
		t.Fatalf("error building request: %v", err)
	}
	request.Host = "shost"
	request.RemoteAddr = "1.2.3.4"
	user := goidentity.NewUser("jcmturner")
	ctx := context.WithValue(request.Context(), goidentity.CTXKey, user)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request.WithContext(ctx))

	t.Logf("%s\n", b.String())
}
