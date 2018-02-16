package httphandling

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/config"
	goidentity "gopkg.in/jcmturner/goidentity.v1"
	"gopkg.in/jcmturner/gokrb5.v4/service"
	"gopkg.in/ldap.v2"
	"net/http"
	"reflect"
	"strings"
	"time"
)

const (
	AuthMechanismNegotiate = "Negotiate"
	AuthMechanismBasic     = "Basic"
	AuthMechanismBearer    = "Bearer"
)

func AuthnHandler(inner http.Handler, c *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the audit log line template
		auditLine, err := newAuditLogLine("Authentication", c)
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcodes.AuthenticationError, "Error processing authentication")
		}

		var id goidentity.Identity
		if sid, ok, _ := getSession(r, c); ok {
			// Request contains cookie for a valid session. Use ID from session cache.
			id = sid
			auditLine.EventType = "Authenication via session"
		} else {
			// Get the authenticator based on what the client specifies in the Authorization header and the server's configuration
			authenticator, err := getAuthenticator(r, c)
			if err != nil {
				auditLine.EventType = "Failed Authentication"
				auditLog(auditLine, err.Error(), r, c)
				respondUnauthorized(w, c)
				return
			}

			// Authenitcate the user
			var authed bool
			id, authed, err = authenticator.Authenticate()
			if err != nil {
				e := "Authentication error with mechanism " + authenticator.Mechanism()
				c.ApplicationLogf("%s: %v", e, err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.AuthenticationError, e)
				return
			}
			if !authed {
				auditLine.EventType = "Authentication Failed"
				auditLog(auditLine, "Client credentials invalid", r, c)
				respondUnauthorized(w, c)
				return
			}
			auditLine.EventType = "Authentication Successful"
			// Set the session cookie
			err = setSession(w, id, c)
			if err != nil {
				c.ApplicationLogf("error setting user's session: %v", err)
			}
		}

		// Audit log
		auditLine.Username = id.UserName()
		auditLine.UserDomain = id.Domain()
		auditLine.UserSessionID = id.SessionID()
		auditLog(auditLine, "Client credentials valid", r, c)

		// Set the request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, goidentity.CTXKey, id)
		r.WithContext(ctx)

		// Serve the inner wrapped handler
		inner.ServeHTTP(w, r)
	})
}

func getAuthenticator(r *http.Request, c *config.Config) (authenticator goidentity.Authenticator, err error) {
	mech, value, err := ParseAuthorizationHeader(r)
	if err != nil {
		err = errors.New("could not parse authorization header")
		return
	}

	switch mech {
	case AuthMechanismNegotiate:
		if !c.Server.Authentication.Kerberos.Enabled {
			err = fmt.Errorf("%s mechanism attempted by client but disabled in server configuration", mech)
			return
		}
		a := new(service.SPNEGOAuthenticator)
		a.Keytab = c.Server.Authentication.Kerberos.Keytab
		a.ServiceAccount = c.Server.Authentication.Kerberos.ServiceAccount
		a.ClientAddr = r.RemoteAddr
		a.SPNEGOHeaderValue = value
		authenticator = a
	case AuthMechanismBasic:
		if !c.Server.Authentication.Basic.Enabled {
			err = fmt.Errorf("%s mechanism attempted by client but disabled in server configuration", mech)
			return
		}
		switch strings.ToLower(c.Server.Authentication.Basic.Protocol) {
		case "ldap":
			a := new(LDAPBasicAuthenticator)
			a.BasicHeaderValue = value
			a.LDAPConfig = c.Server.Authentication.Basic.LDAP
			authenticator = a
		case "kerberos":
			a := new(service.KRB5BasicAuthenticator)
			a.BasicHeaderValue = value
			a.ServiceAccount = c.Server.Authentication.Basic.Kerberos.ServiceAccount
			a.SPN = c.Server.Authentication.Basic.Kerberos.SPN
			a.Config = c.Server.Authentication.Basic.Kerberos.Conf
			a.ServiceKeytab = c.Server.Authentication.Basic.Kerberos.Keytab
			authenticator = a
		case "static":
			a := new(StaticAuthenticator)
			a.BasicHeaderValue = value
			a.RequiredSecret = c.Server.Authentication.Basic.Static.RequiredSecret
			a.StaticAttribute = c.Server.Authentication.Basic.Static.Attribute
			authenticator = a
		default:
			err = fmt.Errorf("Configuration for basic authentication not valid. Protocol specified as: %v", c.Server.Authentication.Basic.Protocol)
			c.ApplicationLogf(err.Error())
			return
		}
	//case AuthMechanismBearer:
	// TODO
	default:
		err = fmt.Errorf("%s authentication mechanism attempted by client not supported", mech)
		return
	}
	return
}

type LDAPBasicAuthenticator struct {
	BasicHeaderValue string
	domain           string
	username         string
	password         string
	LDAPConfig       config.LDAPBasic
}

func (a LDAPBasicAuthenticator) Authenticate() (i goidentity.Identity, ok bool, err error) {
	a.domain, a.username, a.password, err = ParseBasicHeaderValue(a.BasicHeaderValue)
	if err != nil {
		err = fmt.Errorf("could not parse basic authentication header: %v", err)
		return
	}
	err = a.LDAPConfig.LDAPConn.Bind(a.LDAPConfig.BindUserDN, a.LDAPConfig.BindUserPassword)
	if err != nil {
		err = fmt.Errorf("could not bind to LDAP as %s: %v", a.LDAPConfig.BindUserDN, err)
		return
	}
	var filter string
	if a.LDAPConfig.UserObjectClass != "" {
		filter = fmt.Sprintf("(&(objectClass=%s)(%s=%s))", a.LDAPConfig.UserObjectClass, a.LDAPConfig.UsernameAttribute, a.username)
	} else {
		filter = fmt.Sprintf("(%s=%s)", a.LDAPConfig.UsernameAttribute, a.username)
	}
	if a.LDAPConfig.DisplayNameAttribute == "" {
		a.LDAPConfig.DisplayNameAttribute = a.LDAPConfig.UsernameAttribute
	}
	usReq := ldap.NewSearchRequest(
		a.LDAPConfig.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn", a.LDAPConfig.MembershipAttribute, a.LDAPConfig.DisplayNameAttribute},
		nil,
	)
	usRes, err := a.LDAPConfig.LDAPConn.Search(usReq)
	if err != nil {
		err = fmt.Errorf("could not find user %s in LDAP: %v", a.username, err)
		return
	}
	if len(usRes.Entries) != 1 {
		err = fmt.Errorf("user %s does not exist or too many entries returned: %v", a.username, err)
		return
	}

	err = a.LDAPConfig.LDAPConn.Bind(usRes.Entries[0].DN, a.password)
	if err != nil {
		err = fmt.Errorf("authentication failed for user %s: %v", a.username, err)
		return
	}
	u := goidentity.NewUser(a.username)
	u.SetAuthTime(time.Now().UTC())
	u.SetAuthenticated(true)
	u.SetDisplayName(a.domain + "@" + a.username)
	for g := range usRes.Entries[0].GetAttributeValues(a.LDAPConfig.MembershipAttribute) {
		u.AddAuthzAttribute(usRes.Entries[0].GetAttributeValues(a.LDAPConfig.MembershipAttribute)[g])
	}
	ok = true
	i = &u
	return
}

func (a LDAPBasicAuthenticator) Mechanism() string {
	return "LDAP Basic"
}

// StaticAuthenticator is mainly for testing purposes. Do not use in production.
type StaticAuthenticator struct {
	BasicHeaderValue string
	domain           string
	username         string
	password         string
	RequiredSecret   string
	StaticAttribute  string
}

func (a StaticAuthenticator) Authenticate() (i goidentity.Identity, ok bool, err error) {
	a.domain, a.username, a.password, err = ParseBasicHeaderValue(a.BasicHeaderValue)
	if err != nil {
		err = fmt.Errorf("could not parse basic authentication header: %v", err)
		return
	}
	if a.password != a.RequiredSecret {
		err = fmt.Errorf("authentication failed for user %s@%s", a.username, a.domain)
		return
	}
	u := goidentity.NewUser(a.username)
	u.SetAuthTime(time.Now().UTC())
	u.SetAuthenticated(true)
	u.SetDisplayName(a.domain + "@" + a.username)
	u.SetDomain(a.domain)
	u.AddAuthzAttribute(a.StaticAttribute)
	ok = true
	i = &u
	return
}

func (a StaticAuthenticator) Mechanism() string {
	return "Static Basic"
}

func ParseAuthorizationHeader(r *http.Request) (mechanism, value string, err error) {
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		err = errors.New("request does not have a valid authorization header")
		return
	}
	value = s[1]
	switch strings.ToLower(s[0]) {
	case strings.ToLower(AuthMechanismNegotiate):
		mechanism = AuthMechanismNegotiate
	case strings.ToLower(AuthMechanismBasic):
		mechanism = AuthMechanismBasic
	case strings.ToLower(AuthMechanismBearer):
		mechanism = AuthMechanismBearer
	default:
		err = fmt.Errorf("authentication mechanism attempted by client (%s) not recognised", s[0])
	}
	return
}

func ParseBasicHeaderValue(s string) (domain, username, password string, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	v := string(b)
	if !strings.Contains(v, ":") {
		return "", "", "", errors.New("invalid authorization header value")
	}
	vc := strings.SplitN(v, ":", 2)
	password = vc[1]
	// Domain and username can be specified in 2 formats:
	// <Username> - no domain specified
	// <Domain>\<Username>
	// <Domain>/<Username>
	// <Username>@<Domain>
	if strings.Contains(vc[0], `\`) {
		u := strings.SplitN(vc[0], `\`, 2)
		domain = u[0]
		username = u[1]
	} else if strings.Contains(vc[0], `/`) {
		u := strings.SplitN(vc[0], `/`, 2)
		domain = u[0]
		username = u[1]
	} else if strings.Contains(vc[0], `@`) {
		u := strings.SplitN(vc[0], `@`, 2)
		domain = u[1]
		username = u[0]
	} else {
		username = vc[0]
	}
	return
}

func GetIdentity(ctx context.Context) (id goidentity.Identity, err error) {
	u := ctx.Value(goidentity.CTXKey)
	if u == nil {
		err = errors.New("no identity found in context")
		return
	}
	v := reflect.Indirect(reflect.New(reflect.TypeOf(u)))
	v.Set(reflect.ValueOf(u))
	p := v.Addr().Interface()

	if i, ok := p.(goidentity.Identity); ok {
		id = i
		return
	}
	err = errors.New("invalid identity found in context")
	return
}
