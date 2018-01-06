// +build integration
// To turn on this test use -tags=integration in go test command

package app

import (
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/httphandling"
	"github.com/jcmturner/awsfederation/test"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestApplyDBSchema(t *testing.T) {
	c := config.IntgTest()
	dbs := os.Getenv("TEST_DB_SOCKET")
	if dbs == "" {
		dbs = "127.0.0.1:3306"
	}
	err := ApplyDBSchema(c, dbs, "root", "rootpasswd")
	if err != nil {
		t.Fatalf("Error applying database schema: %v", err)
	}
}

func TestApp_Run(t *testing.T) {
	c := config.IntgTest()
	var a App
	err := a.Initialize(c)
	if err != nil {
		t.Fatalf("Error initialising app: %v", err)
	}

	// Put this into Go routine
	go func() {
		err = a.Run()
		if err != nil {
			t.Fatalf("error running app: %v", err)
		}
	}()

	var tests = []struct {
		Method         string
		AuthRequired   bool
		Path           string
		PostPayload    string
		HttpCode       int
		ResponseString string
	}{
		// Create
		{"POST", true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status "+test.AccountStatusName1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account status with name "+test.AccountStatusName1+" already exists.", http.StatusBadRequest, appcodes.AccountStatusAlreadyExists)},
		// List 1 entry
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountStatuses":[{"ID":%d,"Status":"%s"}]}`, test.AccountStatusID1, test.AccountStatusName1)},
		// Get
		{"GET", false, "/1", "", http.StatusOK, fmt.Sprintf(`{"ID":%d,"Status":"%s"}`, test.AccountStatusID1, test.AccountStatusName1)},
		{"POST", true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status "+test.AccountStatusName2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountStatuses":[{"ID":%d,"Status":"%s"},{"ID":%d,"Status":"%s"}]}`, test.AccountStatusID1, test.AccountStatusName1, test.AccountStatusID2, test.AccountStatusName2)},
		//// Method not allowed
		{"POST", true, "/1", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, "somethingelse"), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", true, "/2", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status with ID 2 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", true, "/2", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account status ID not found.", http.StatusNotFound, appcodes.AccountStatusUnknown)},
		{"PUT", true, "/1", fmt.Sprintf(httphandling.AccountStatusPUTTmpl, 1, "somethingelse"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account status %d updated.", test.AccountStatusID1), http.StatusOK, appcodes.Info)},
	}

	for _, test := range tests {
		url := fmt.Sprintf("http://127.0.0.1:8443"+httphandling.AccountStatusAPIPath, httphandling.APIVersion, test.Path)
		request, err := http.NewRequest(test.Method, url, strings.NewReader(test.PostPayload))
		if err != nil {
			t.Fatalf("error building request: %v", err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("error making request to %s: %v", url, err)
		}
		if test.AuthRequired {
			// Check it was unauthorized before passing auth creds
			assert.Equal(t, http.StatusUnauthorized, response.StatusCode, "Expected unauthorized error")
			// Now authenticated (using testing static auth)
			request, err = http.NewRequest(test.Method, url, strings.NewReader(test.PostPayload))
			request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser@TESTING:"+config.MockStaticSecret)))
			response, err = http.DefaultClient.Do(request)
			if err != nil {
				t.Fatalf("error making request to %s got response %+v: %v", url, response, err)
			}
		}
		assert.Equal(t, test.HttpCode, response.StatusCode, fmt.Sprintf("Expected HTTP code: %d got: %d (%s %s)", test.HttpCode, response.StatusCode, test.Method, url))
		bodyBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("error getting response body from %s: %v", url, err)
		}
		assert.Equal(t, test.ResponseString, string(bodyBytes), fmt.Sprintf("Response not as expected (%s %s)", test.Method, url))
	}
}
