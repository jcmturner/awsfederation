package errors

import (
	"fmt"
	"github.com/jcmturner/awsfederation/appcode"
)

type ErrFederationUserNotFound struct {
	AppCode int
	Text string
}

func (e ErrFederationUserNotFound) Error() string {
	return e.Text
}

func (e ErrFederationUserNotFound) Errorf(format string, a ...interface{}) ErrFederationUserNotFound {
	e.Text = fmt.Sprintf(format, a)
	e.AppCode = appcode.FEDERATIONUSER_UNKNOWN
	return e
}
