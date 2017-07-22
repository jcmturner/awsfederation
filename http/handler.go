package http

import (
	"net/http"
)

func wrapCommonHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
		return
	})
}

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/federationuser", handleFederationUser())

}
