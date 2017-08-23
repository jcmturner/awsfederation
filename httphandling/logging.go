package httphandling

import (
	"encoding/json"
	"github.com/jcmturner/awsfederation/config"
	"net/http"
	"net/url"
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

func accessLogger(inner http.Handler, c *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := NewResponseWriterWrapper(w)
		inner.ServeHTTP(ww, r)
		l := AccessLog{
			SourceIP:    r.RemoteAddr,
			Username:    "-",
			UserRealm:   "-",
			StatusCode:  ww.Status(),
			Method:      r.Method,
			ServerHost:  r.Host,
			Path:        r.RequestURI,
			QueryString: r.URL.RawQuery,
			Time:        start,
			Duration:    time.Since(start),
		}
		id, err := GetIdentity(r.Context())
		if err == nil {
			l.Username = id.UserName()
			l.UserRealm = id.Domain()
		}
		c.AccessLog(l)
	})
}

type auditDetail struct {
	RemoteAddr string
	RequestURI string
	Message    string
}

func auditLog(l config.AuditLogLine, msg string, r *http.Request, c *config.Config) {
	d := auditDetail{
		RemoteAddr: r.RemoteAddr,
		RequestURI: r.RequestURI,
		Message:    msg,
	}
	b, _ := json.Marshal(d)
	l.Detail = url.QueryEscape(string(b))
	c.AccessLog(l)
}
