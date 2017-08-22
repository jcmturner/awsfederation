package apperrors

import (
	"fmt"
	"github.com/jcmturner/awsfederation/appcode"
)

type ErrInvalidAuthentication struct {
	AppCode int
	Text    string
}

type ErrUnauthorized struct {
	AppCode int
	Text    string
}

type ErrFederationFailure struct {
	AppCode int
	Text    string
}

type ErrFederationUserNotFound struct {
	AppCode int
	Text    string
}

func (e ErrInvalidAuthentication) Error() string {
	return e.Text
}

func (e ErrInvalidAuthentication) Errorf(format string, a ...interface{}) ErrInvalidAuthentication {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = appcode.FEDERATIONUSER_UNKNOWN
	return e
}

func (e ErrUnauthorized) Error() string {
	return e.Text
}

func (e ErrUnauthorized) Errorf(format string, a ...interface{}) ErrUnauthorized {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = appcode.FEDERATIONUSER_UNKNOWN
	return e
}

func (e ErrFederationFailure) Error() string {
	return e.Text
}

func (e ErrFederationFailure) Errorf(format string, a ...interface{}) ErrFederationFailure {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = appcode.FEDERATIONUSER_UNKNOWN
	return e
}

func (e ErrFederationUserNotFound) Error() string {
	return e.Text
}

func (e ErrFederationUserNotFound) Errorf(format string, a ...interface{}) ErrFederationUserNotFound {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = appcode.FEDERATIONUSER_UNKNOWN
	return e
}
