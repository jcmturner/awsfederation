package httphandling

import (
	"net/http"
	"github.com/jcmturner/awsfederation/config"
	"encoding/json"
)

func WrapCommonHandler(inner http.Handler, c config.Config) http.Handler {

	//Wrap with access logger
	inner = AccessLogger(inner, c)

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

type JSONResponseError struct {
	Error string
	HTTPCode int
	ErrorCode int
}

func respondWithError(w http.ResponseWriter, httpCode, errorCode int, message string) {
	e := JSONResponseError{
		Error: message,
		HTTPCode: httpCode,
		ErrorCode: errorCode,
	}
	respondWithJSON(w, httpCode, e)
}

func respondWithJSON(w http.ResponseWriter, httpCode int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(httpCode)
	w.Write(response)
}