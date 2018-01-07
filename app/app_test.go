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
		Endpoint       string
		AuthRequired   bool
		Path           string
		PostPayload    string
		HttpCode       int
		ResponseString string
	}{
		// Account Status
		// Create
		{"POST", httphandling.AccountStatusAPI, true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status "+test.AccountStatusName1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", httphandling.AccountStatusAPI, true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account status with name "+test.AccountStatusName1+" already exists.", http.StatusBadRequest, appcodes.AccountStatusAlreadyExists)},
		// List 1 entry
		{"GET", httphandling.AccountStatusAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountStatuses":[{"ID":%d,"Status":"%s"}]}`, test.AccountStatusID1, test.AccountStatusName1)},
		// Get
		{"GET", httphandling.AccountStatusAPI, false, "/1", "", http.StatusOK, fmt.Sprintf(`{"ID":%d,"Status":"%s"}`, test.AccountStatusID1, test.AccountStatusName1)},
		{"POST", httphandling.AccountStatusAPI, true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status "+test.AccountStatusName2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", httphandling.AccountStatusAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountStatuses":[{"ID":%d,"Status":"%s"},{"ID":%d,"Status":"%s"}]}`, test.AccountStatusID1, test.AccountStatusName1, test.AccountStatusID2, test.AccountStatusName2)},
		//// Method not allowed
		{"POST", httphandling.AccountStatusAPI, true, "/1", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, "somethingelse"), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", httphandling.AccountStatusAPI, true, "/2", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status with ID 2 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountStatusAPI, true, "/2", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account status ID not found.", http.StatusNotFound, appcodes.AccountStatusUnknown)},
		{"PUT", httphandling.AccountStatusAPI, true, "/1", fmt.Sprintf(httphandling.AccountStatusPUTTmpl, 1, "somethingelse"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account status %d updated.", test.AccountStatusID1), http.StatusOK, appcodes.Info)},

		// Account Class
		// Create
		{"POST", httphandling.AccountClassAPI, true, "", fmt.Sprintf(httphandling.AccountClassPOSTTmpl, test.AccountClassName1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account class "+test.AccountClassName1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", httphandling.AccountClassAPI, true, "", fmt.Sprintf(httphandling.AccountClassPOSTTmpl, test.AccountClassName1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account class with name "+test.AccountClassName1+" already exists.", http.StatusBadRequest, appcodes.AccountClassAlreadyExists)},
		// List 1 entry
		{"GET", httphandling.AccountClassAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountClasses":[{"ID":%d,"Class":"%s"}]}`, test.AccountClassID1, test.AccountClassName1)},
		// Get
		{"GET", httphandling.AccountClassAPI, false, "/1", "", http.StatusOK, fmt.Sprintf(`{"ID":%d,"Class":"%s"}`, test.AccountClassID1, test.AccountClassName1)},
		{"POST", httphandling.AccountClassAPI, true, "", fmt.Sprintf(httphandling.AccountClassPOSTTmpl, test.AccountClassName2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account class "+test.AccountClassName2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", httphandling.AccountClassAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountClasses":[{"ID":%d,"Class":"%s"},{"ID":%d,"Class":"%s"}]}`, test.AccountClassID1, test.AccountClassName1, test.AccountClassID2, test.AccountClassName2)},
		//// Method not allowed
		{"POST", httphandling.AccountClassAPI, true, "/1", fmt.Sprintf(httphandling.AccountClassPOSTTmpl, "somethingelse"), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", httphandling.AccountClassAPI, true, "/2", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account class with ID 2 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountClassAPI, true, "/2", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account class ID not found.", http.StatusNotFound, appcodes.AccountClassUnknown)},
		{"PUT", httphandling.AccountClassAPI, true, "/1", fmt.Sprintf(httphandling.AccountClassPUTTmpl, 1, "somethingelse"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account class %d updated.", test.AccountClassID1), http.StatusOK, appcodes.Info)},
	}

	for _, test := range tests {
		url := fmt.Sprintf("http://127.0.0.1:8443/%s/%s%s", httphandling.APIVersion, test.Endpoint, test.Path)
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
