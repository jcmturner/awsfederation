package appcodes

import (
	"fmt"
)

type ErrInvalidAuthentication struct {
	AppCode int
	Text    string
}

type ErrUnauthorized struct {
	AppCode int
	Text    string
}

type ErrAssumeRoleFailure struct {
	AppCode int
	Text    string
}

type ErrFederationUserNotFound struct {
	AppCode int
	Text    string
}

type ErrBadPostData struct {
	Code int
	Text string
}

func (e ErrInvalidAuthentication) Error() string {
	return e.Text
}

func (e ErrInvalidAuthentication) Errorf(format string, a ...interface{}) ErrInvalidAuthentication {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = InvalidAuthentication
	return e
}

func (e ErrUnauthorized) Error() string {
	return e.Text
}

func (e ErrUnauthorized) Errorf(format string, a ...interface{}) ErrUnauthorized {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = Unauthorized
	return e
}

func (e ErrAssumeRoleFailure) Error() string {
	return e.Text
}

func (e ErrAssumeRoleFailure) Errorf(format string, a ...interface{}) ErrAssumeRoleFailure {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = AssumeRoleError
	return e
}

func (e ErrFederationUserNotFound) Error() string {
	return e.Text
}

func (e ErrFederationUserNotFound) Errorf(format string, a ...interface{}) ErrFederationUserNotFound {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = FederationUserUnknown
	return e
}

func (e ErrBadPostData) Error() string {
	return e.Text
}

func (e ErrBadPostData) Errorf(format string, a ...interface{}) ErrBadPostData {
	e.Text = fmt.Sprintf(format, a)
	e.Code = BadData
	return e
}
