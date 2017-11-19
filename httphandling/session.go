package httphandling

import (
	"encoding/base64"
	"github.com/gorilla/securecookie"
	"github.com/jcmturner/awsfederation/config"
	"gopkg.in/jcmturner/goidentity.v1"
	"net/http"
	"sync"
	"time"
	"fmt"
	"errors"
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
// Durations is the period to wait between cache garbage collection.
func getAuthSessionCache(d time.Duration) *authSessionCache {
	// Create a singleton of the ReplayCache and start a background thread to regularly clean out old entries
	once.Do(func() {
		sessionCache = authSessionCache{
			Entries: make(map[string]authSessionEntry),
		}
		go func() {
			for {
				time.Sleep(time.Duration(2) * time.Minute)
				sessionCache.clearOldEntries()
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
	getAuthSessionCache(time.Duration(c.Server.Authentication.SessionDuration)*time.Minute).addSessionEntry(sessionSecret, id, c)
	return nil
}

func getSession(r *http.Request, c *config.Config) (goidentity.Identity, bool, error) {
	return getAuthSessionCache(time.Duration(c.Server.Authentication.SessionDuration)*time.Minute).validateSession(r, c)
}

func processSessionCookie(c *http.Cookie) (sessionID, sessionSecret string, err error) {
	value := make(map[string]string)
	var s = securecookie.New(hashKey, blockKey)
	err = s.Decode(sessionCookieName, c.Value, &value)
	if err != nil {
		err = fmt.Errorf("error decoding session cookie: %v", err)
		return
	}
	sessionID, ok := value[valueKeySessionID]
	if !ok {
		err = errors.New("error processing session cookie, session ID not found.")
		return
	}
	sessionSecret, ok = value[valueKeySessionSecret]
	if !ok {
		err = errors.New("error processing session cookie, session secret not found.")
		return
	}
	return
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

func (a *authSessionCache) clearOldEntries() {
	a.mux.Lock()
	defer a.mux.Unlock()
	for i, e := range a.Entries {
		if e.Expires.Before(time.Now().UTC()) || e.Timeout.Before(time.Now().UTC()) {
			delete(a.Entries, i)
		}
	}
}


func (a *authSessionCache) validateSession(r *http.Request, c *config.Config) (id goidentity.Identity, ok bool, err error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		err = fmt.Errorf("session cookie not found in request: %v", err)
		return
	}

	// Get values of session ID and session secret provided in the request
	rSessID, rSessSecet, err := processSessionCookie(cookie)
	if err != nil {
		return
	}

	// Look up the session in the cache and check the SessionID and Secret pairing matches.
	a.mux.Lock()
	defer a.mux.Unlock()
	e, ok := a.Entries[rSessSecet]
	if !ok {
		err = errors.New("session not found in the session cache.")
		return
	}
	id = e.Identity
	if e.Expires.Before(time.Now().UTC()) || e.Timeout.Before(time.Now().UTC()) {
		err = errors.New("session found in the session cache has expired or is not yet valid.")
		return
	}
	if rSessID != id.SessionID() {
		err = errors.New("session ID in request does no match that in the session cache.")
		return
	}

	// Session is valid. Renew the session active timeout.
	e.Timeout = time.Now().UTC().Add(time.Minute * time.Duration(c.Server.Authentication.ActiveSessionTimeout))
	ok = true
	return
}
