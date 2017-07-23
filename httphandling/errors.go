package httphandling

import (
	"fmt"
	"net/http"
)

type ErrBadPostData struct {
	Code int
	Text string
}

func (e ErrBadPostData) Error() string {
	return e.Text
}

func (e ErrBadPostData) Errorf(format string, a ...interface{}) ErrBadPostData {
	e.Text = fmt.Sprintf(format, a)
	e.Code = http.StatusBadRequest
	return e
}
