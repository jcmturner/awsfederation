package httphandling

import (
	"encoding/base64"
	"github.com/gorilla/securecookie"
	"github.com/jcmturner/awsfederation/config"
	"gopkg.in/jcmturner/goidentity.v1"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookieName     = "AWSFederationAuthSession"
	valueKeySessionID     = "SessionID"
	valueKeySessionSecret = "SessionSecret"
)

var hashKey []byte = securecookie.GenerateRandomKey(64)
var blockKey []byte = securecookie.GenerateRandomKey(32)

// Instance of the ServiceCache. This needs to be a singleton.
var sessionCache authSessionCache
var once sync.Once

// GetAuthSessionCache returns a pointer to the Cache singleton.
func GetAuthSessionCache(d time.Duration) *authSessionCache {
	// Create a singleton of the ReplayCache and start a background thread to regularly clean out old entries
	once.Do(func() {
		sessionCache = authSessionCache{
			Entries: make(map[string]authSessionEntry),
		}
		go func() {
			for {
				time.Sleep(d)
				sessionCache.clearOldEntries(d)
			}
		}()
	})
	return &sessionCache
}

func setSession(w http.ResponseWriter, id goidentity.Identity, c *config.Config) error {
	var s = securecookie.New(hashKey, blockKey)
	sessionSecret := base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(64))

	value := map[string]string{
		valueKeySessionID:     id.SessionID(),
		valueKeySessionSecret: sessionSecret,
	}

	et := time.Now().UTC().Add(time.Minute * time.Duration(c.Server.Authentication.SessionDuration))

	encoded, err := s.Encode(sessionCookieName, value)
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:     sessionCookieName,
		Value:    encoded,
		Expires:  et,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
	GetAuthSessionCache(time.Duration(c.Server.Authentication.SessionDuration)*time.Minute).addSessionEntry(sessionSecret, id, c)
	return nil
}

func getSession(r *http.Request, c *config.Config) (goidentity.Identity, bool) {
	return GetAuthSessionCache(time.Duration(c.Server.Authentication.SessionDuration)*time.Minute).validateSession(r, c)
}

type authSessionCache struct {
	Entries map[string]authSessionEntry
	mux     sync.RWMutex
}

type authSessionEntry struct {
	Identity goidentity.Identity
	Timeout  time.Time
	Expires  time.Time
}

// AddEntry adds an entry to the Cache.
func (a *authSessionCache) addSessionEntry(sessionSecret string, id goidentity.Identity, c *config.Config) {
	a.mux.Lock()
	defer a.mux.Unlock()
	a.Entries[sessionSecret] = authSessionEntry{
		Identity: id,
		Timeout:  time.Now().UTC().Add(time.Minute * time.Duration(c.Server.Authentication.ActiveSessionTimeout)),
		Expires:  time.Now().UTC().Add(time.Minute * time.Duration(c.Server.Authentication.SessionDuration)),
	}
}

func (a *authSessionCache) clearOldEntries(d time.Duration) {
	a.mux.Lock()
	defer a.mux.Unlock()
	for i, e := range a.Entries {
		if e.Expires.Before(time.Now().UTC()) || e.Timeout.Before(time.Now().UTC()) {
			delete(a.Entries, i)
		}
	}
}

func (a *authSessionCache) validateSession(r *http.Request, c *config.Config) (id goidentity.Identity, ok bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		ok = false
		return
	}
	value := make(map[string]string)
	var s = securecookie.New(hashKey, blockKey)
	err = s.Decode(sessionCookieName, cookie.Value, &value)
	if err != nil {
		ok = false
		return
	}
	rSessionID, ok := value[valueKeySessionID]
	if !ok {
		ok = false
		return
	}
	rSessionSecret, ok := value[valueKeySessionSecret]
	if !ok {
		ok = false
		return
	}

	// Look up the session in the cache and check the SessionID and Secret pairing matches.
	a.mux.Lock()
	defer a.mux.Unlock()
	e, ok := a.Entries[rSessionSecret]
	if !ok {
		ok = false
		return
	}
	id = e.Identity
	if e.Expires.Before(time.Now().UTC()) || e.Timeout.Before(time.Now().UTC()) {
		ok = false
		return
	}
	// Renew the session timeout
	e.Timeout = time.Now().UTC().Add(time.Minute * time.Duration(c.Server.Authentication.ActiveSessionTimeout))
	if rSessionID != id.SessionID() {
		ok = false
		return
	}
	ok = true
	return
}
