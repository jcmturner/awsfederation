package httphandling

import (
	"encoding/json"
	"fmt"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/config"
	"net/http"
)

func WrapCommonHandler(inner http.Handler, authn bool, c *config.Config) http.Handler {

	//Wrap in authentication
	if authn {
		inner = AuthnHandler(inner, c)
	}
	//Wrap with access logger
	inner = accessLogger(inner, c)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w = setHeaders(w)
		inner.ServeHTTP(w, r)
		return
	})
}

func setHeaders(w http.ResponseWriter) http.ResponseWriter {
	w.Header().Set("Cache-Control", "no-store")
	//OWASP recommended headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "deny")
	return w
}

type JSONGenericResponse struct {
	Message         string
	HTTPCode        int
	ApplicationCode int
}

func respondGeneric(w http.ResponseWriter, httpCode, appCode int, message string) {
	e := JSONGenericResponse{
		Message:         message,
		HTTPCode:        httpCode,
		ApplicationCode: appCode,
	}
	respondWithJSON(w, httpCode, e)
}

func respondWithJSON(w http.ResponseWriter, httpCode int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(httpCode)
	w.Write(response)
}

func respondUnauthorized(w http.ResponseWriter, c *config.Config) {
	if c.Server.Authentication.Kerberos.Enabled {
		w.Header().Set("WWW-Authenticate", "Negotiate")
	}
	if c.Server.Authentication.Basic.Enabled {
		hv := "Basic"
		if c.Server.Authentication.Basic.Realm != "" {
			hv = hv + ` realm="` + c.Server.Authentication.Basic.Realm + `"`
		}
		w.Header().Set("WWW-Authenticate", hv)
	}
	respondGeneric(w, http.StatusUnauthorized, appcodes.Unauthorized, "Unathorized")
}

func MethodNotAllowed() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondGeneric(w, http.StatusMethodNotAllowed, appcodes.BadData, fmt.Sprintf("The %s method cannot be performed against this part of the API", r.Method))
		return
	})
}
