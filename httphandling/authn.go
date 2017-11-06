package httphandling

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hashicorp/go-uuid"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/config"
	goidentity "gopkg.in/jcmturner/goidentity.v1"
	"gopkg.in/jcmturner/gokrb5.v2/service"
	"gopkg.in/ldap.v2"
	"net/http"
	"strings"
	"time"
)

func AuthnHandler(inner http.Handler, c *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 {
			respondUnauthorized(w, c)
			return
		}
		var id goidentity.Identity
		eventUUID, err := uuid.GenerateUUID()
		if err != nil {
			c.ApplicationLogf("error generating uuid for audit log event during authentication: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.AuthenticationError, "Error processing authentication")
			return
		}
		auditLine := config.AuditLogLine{
			Username:      "-",
			UserDomain:    "-",
			UserSessionID: "00000000-0000-0000-0000-000000000000",
			Time:          time.Now().UTC(),
			EventType:     "Authentication",
			UUID:          eventUUID,
		}
		var authenticator goidentity.Authenticator
		switch s[0] {
		case "Negotiate":
			if !c.Server.Authentication.Kerberos.Enabled {
				auditLine.EventType = "Failed Authentication"
				auditLog(auditLine, "Negotiate mechanism attempted by client but disabled in server configuration", r, c)
				respondUnauthorized(w, c)
				return
			}
			a := new(service.SPNEGOAuthenticator)
			a.Keytab = c.Server.Authentication.Kerberos.Keytab
			a.ServiceAccount = c.Server.Authentication.Kerberos.ServiceAccount
			a.ClientAddr = r.RemoteAddr
			a.SPNEGOHeaderValue = s[1]
			authenticator = a
		case "Basic":
			if !c.Server.Authentication.Basic.Enabled {
				auditLine.EventType = "Failed Authentication"
				auditLog(auditLine, "Basic mechanism attempted by client but disabled in server configuration", r, c)
				respondUnauthorized(w, c)
				return
			}
			switch strings.ToLower(c.Server.Authentication.Basic.Protocol) {
			case "ldap":
				a := new(LDAPBasicAuthenticator)
				a.BasicHeaderValue = s[1]
				a.LDAPConfig = c.Server.Authentication.Basic.LDAP
				authenticator = a
			case "kerberos":
				a := new(service.KRB5BasicAuthenticator)
				a.BasicHeaderValue = s[1]
				a.ServiceAccount = c.Server.Authentication.Basic.Kerberos.ServiceAccount
				a.SPN = c.Server.Authentication.Basic.Kerberos.SPN
				a.Config = c.Server.Authentication.Basic.Kerberos.Conf
				a.ServiceKeytab = c.Server.Authentication.Basic.Kerberos.Keytab
				authenticator = a
			case "static":
				a := new(StaticAuthenticator)
				a.BasicHeaderValue = s[1]
				a.RequiredSecret = c.Server.Authentication.Basic.Static.RequiredSecret
				a.StaticAttribute = c.Server.Authentication.Basic.Static.Attribute
				authenticator = a
			default:
				c.ApplicationLogf("Configuration for basic authentication not valid. Protocol specified as: %v", c.Server.Authentication.Basic.Protocol)
				respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "Basic authentication not availbale")
				return
			}
		//case "Bearer":
		// TODO
		default:
			auditLine.EventType = "Failed Authentication"
			msg := fmt.Sprintf("Authentication mechanism attempted by client (%s) not recognised", s[0])
			auditLog(auditLine, msg, r, c)
			respondUnauthorized(w, c)
			return
		}

		id, authed, err := authenticator.Authenticate()
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
		auditLine.Username = id.UserName()
		auditLine.UserDomain = id.Domain()
		auditLine.EventType = "Authentication Successful"
		auditLine.UserSessionID = id.SessionID()
		auditLog(auditLine, "Client credentials valid", r, c)
		ctx := r.Context()
		ctx = context.WithValue(ctx, goidentity.CTXKey, id)
		r.WithContext(ctx)
		inner.ServeHTTP(w, r)
	})
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
	u.AddAuthzAttribute(a.StaticAttribute)
	ok = true
	i = &u
	return
}

func (a StaticAuthenticator) Mechanism() string {
	return "Static Basic"
}

func ParseBasicHeaderValue(s string) (domain, username, password string, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	v := string(b)
	vc := strings.SplitN(v, ":", 2)
	password = vc[1]
	// Domain and username can be specified in 2 formats:
	// <Username> - no domain specified
	// <Domain>\<Username>
	// <Username>@<Domain>
	if strings.Contains(vc[0], `\`) {
		u := strings.SplitN(vc[0], `\`, 2)
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
	if u, ok := ctx.Value(goidentity.CTXKey).(goidentity.Identity); ok {
		id = u
		return
	} else {
		err = errors.New("No identity found in context")
		return
	}
}
