package httphandling

import (
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/awsfederation/test"
	"github.com/stretchr/testify/assert"
	"gopkg.in/DATA-DOG/go-sqlmock.v1"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountStatus(t *testing.T) {
	c, _, _, ep, stmtMap, s := test.TestEnv(t)
	defer s.Close()
	fc := make(federationuser.FedUserCache)
	rt := NewRouter(c, stmtMap, &fc)

	var tests = []struct {
		Method         string
		AuthRequired   bool
		Path           string
		PostPayload    string
		HttpCode       int
		ResponseString string
	}{
		// Create
		{"POST", true, "", fmt.Sprintf(AccountStatusPOSTTmpl, test.AccountStatusName1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status "+test.AccountStatusName1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", true, "", fmt.Sprintf(AccountStatusPOSTTmpl, test.AccountStatusName1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account status with name "+test.AccountStatusName1+" already exists.", http.StatusBadRequest, appcodes.AccountStatusAlreadyExists)},
		// List 1 entry
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountStatuses":[{"ID":%d,"Status":"%s"}]}`, test.AccountStatusID1, test.AccountStatusName1)},
		// Get
		{"GET", false, "/1", "", http.StatusOK, fmt.Sprintf(`{"ID":%d,"Status":"%s"}`, test.AccountStatusID1, test.AccountStatusName1)},
		{"POST", true, "", fmt.Sprintf(AccountStatusPOSTTmpl, test.AccountStatusName2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status "+test.AccountStatusName2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountStatuses":[{"ID":%d,"Status":"%s"},{"ID":%d,"Status":"%s"}]}`, test.AccountStatusID1, test.AccountStatusName1, test.AccountStatusID2, test.AccountStatusName2)},
		//// Method not allowed
		{"POST", true, "/1", fmt.Sprintf(AccountStatusPOSTTmpl, "somethingelse"), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", true, "/2", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status with ID 2 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", true, "/2", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account status ID not found.", http.StatusNotFound, appcodes.AccountStatusUnknown)},
		{"PUT", true, "/1", fmt.Sprintf(AccountStatusPUTTmpl, 1, "somethingelse"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account status %d updated.", test.AccountStatusID1), http.StatusOK, appcodes.Info)},
	}
	// Set the expected database calls that are performed as part of the table tests
	ep[database.StmtKeyAcctStatusInsert].ExpectExec().WithArgs(test.AccountStatusName1).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyAcctStatusInsert].ExpectExec().WithArgs(test.AccountStatusName1).WillReturnResult(sqlmock.NewResult(1, 0))
	rows1 := sqlmock.NewRows([]string{"id", "status"}).
		AddRow(1, test.AccountStatusName1)
	ep[database.StmtKeyAcctStatusSelectList].ExpectQuery().WillReturnRows(rows1)
	rows1a := sqlmock.NewRows([]string{"id", "status"}).
		AddRow(1, test.AccountStatusName1)
	ep[database.StmtKeyAcctStatusSelect].ExpectQuery().WithArgs(test.AccountStatusID1).WillReturnRows(rows1a)
	ep[database.StmtKeyAcctStatusInsert].ExpectExec().WithArgs(test.AccountStatusName2).WillReturnResult(sqlmock.NewResult(1, 1))
	rows2 := sqlmock.NewRows([]string{"id", "status"}).
		AddRow(1, test.AccountStatusName1).
		AddRow(2, test.AccountStatusName2)
	ep[database.StmtKeyAcctStatusSelectList].ExpectQuery().WillReturnRows(rows2)
	ep[database.StmtKeyAcctStatusDelete].ExpectExec().WithArgs(test.AccountStatusID2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyAcctStatusDelete].ExpectExec().WithArgs(test.AccountStatusID2).WillReturnResult(sqlmock.NewResult(0, 0))
	ep[database.StmtKeyAcctStatusUpdate].ExpectExec().WithArgs("somethingelse", test.AccountStatusID1).WillReturnResult(sqlmock.NewResult(0, 1))

	for _, test := range tests {
		url := fmt.Sprintf(AccountStatusAPIPath, APIVersion, test.Path)
		request, err := http.NewRequest(test.Method, url, strings.NewReader(test.PostPayload))
		if err != nil {
			t.Fatalf("error building request: %v", err)
		}
		response := httptest.NewRecorder()
		rt.ServeHTTP(response, request)
		if test.AuthRequired {
			// Check it was unauthorized before passing auth creds
			assert.Equal(t, http.StatusUnauthorized, response.Code, "Expected unauthorized error")
			// Now authenticated (using testing static auth)
			response = httptest.NewRecorder()
			request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser@TESTING:"+config.MockStaticSecret)))
			rt.ServeHTTP(response, request)
		}
		assert.Equal(t, test.HttpCode, response.Code, fmt.Sprintf("Expected HTTP code: %d got: %d (%s %s)", test.HttpCode, response.Code, test.Method, url))
		assert.Equal(t, test.ResponseString, response.Body.String(), fmt.Sprintf("Response not as expected (%s %s)", test.Method, url))
	}
}
