package httphandling

import (
	"github.com/jcmturner/awsfederation/config"
	"net/http"
	"time"
)

type AccessLog struct {
	SourceIP    string        `json:"SourceIP"`
	Username    string        `json:"Username"`
	UserRealm   string        `json:"UserRealm"`
	StatusCode  int           `json:"StatusCode"`
	Method      string        `json:"Method"`
	ServerHost  string        `json:"ServerHost"`
	Path        string        `json:"Path"`
	QueryString string        `json:"QueryString"`
	Time        time.Time     `json:"Time"`
	Duration    time.Duration `json:"Duration"`
}

func AccessLogger(inner http.Handler, c *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := NewResponseWriterWrapper(w)
		inner.ServeHTTP(ww, r)
		l := AccessLog{
			SourceIP:    r.RemoteAddr,
			Username:    "placeholder",
			UserRealm:   "realmplaceholder",
			StatusCode:  ww.Status(),
			Method:      r.Method,
			ServerHost:  r.Host,
			Path:        r.RequestURI,
			QueryString: r.URL.RawQuery,
			Time:        start,
			Duration:    time.Since(start),
		}
		err := c.Server.Logging.AccessEncoder.Encode(l)
		if err != nil {
			c.ApplicationLogf("Could not log access event: %v\n", err)
		}
	})
}
