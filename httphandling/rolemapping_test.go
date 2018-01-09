package httphandling

import (
	"encoding/base64"
	"encoding/json"
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

const ()

func TestRoleMapping(t *testing.T) {
	c, _, _, ep, stmtMap, s := test.TestEnv(t)
	defer s.Close()
	fc := make(federationuser.FedUserCache)
	rt := NewRouter(c, stmtMap, &fc)

	var tests = []struct {
		Method         string
		Endpoint       string
		AuthRequired   bool
		Path           string
		PostPayload    string
		HttpCode       int
		ResponseString string
	}{
		// Create
		{"POST", RoleMappingAPI, true, "", fmt.Sprintf(RoleMappingPOSTTmpl, test.RoleARN1, test.AuthzAttrib1), http.StatusCreated, fmt.Sprintf(test.CreatedResponseTmpl, "", "")},
		// List 1 entry
		{"GET", RoleMappingAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"RoleMappings":[`+RoleMappingGETTmpl+`]}`, test.UUID1, test.RoleARN1, test.AuthzAttrib1, test.AWSAccountID1)},
		// Get
		{"GET", RoleMappingAPI, false, "/" + test.UUID1, "", http.StatusOK, fmt.Sprintf(RoleMappingGETTmpl, test.UUID1, test.RoleARN1, test.AuthzAttrib1, test.AWSAccountID1)},
		{"POST", RoleMappingAPI, true, "", fmt.Sprintf(RoleMappingPOSTTmpl, test.RoleARN2, test.AuthzAttrib2), http.StatusCreated, fmt.Sprintf(test.CreatedResponseTmpl, "", "")},
		//// List multiple
		{"GET", RoleMappingAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"RoleMappings":[`+RoleMappingGETTmpl+`,`+RoleMappingGETTmpl+`]}`, test.UUID1, test.RoleARN1, test.AuthzAttrib1, test.AWSAccountID1, test.UUID2, test.RoleARN2, test.AuthzAttrib2, test.AWSAccountID2)},
		//// Method not allowed
		{"POST", RoleMappingAPI, true, "/" + test.UUID1, fmt.Sprintf(RoleMappingPOSTTmpl, test.RoleARN1, test.AuthzAttrib2), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", RoleMappingAPI, true, "/" + test.UUID2, "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Role Mapping with ID "+test.UUID2+" deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", RoleMappingAPI, true, "/" + test.UUID2, "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Role Mapping ID not found.", http.StatusNotFound, appcodes.RoleMappingUnknown)},
		{"PUT", RoleMappingAPI, true, "/" + test.UUID1, fmt.Sprintf(RoleMappingPUTTmpl, test.UUID1, test.RoleARN1, test.AuthzAttrib2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Role Mapping %s updated.", test.UUID1), http.StatusOK, appcodes.Info)},
	}

	// Set the expected database calls that are performed as part of the table tests
	ep[database.StmtKeyRoleMappingInsert].ExpectExec().WithArgs(sqlmock.AnyArg(), test.AWSAccountID1, test.RoleARN1, test.AuthzAttrib1, "", 0, "").WillReturnResult(sqlmock.NewResult(0, 1))
	rows1 := sqlmock.NewRows([]string{"id", "acctid", "rolearn", "authz", "policy", "duration", "sessfmt"}).
		AddRow(test.UUID1, test.AWSAccountID1, test.RoleARN1, test.AuthzAttrib1, "", 0, "")
	ep[database.StmtKeyRoleMappingSelectList].ExpectQuery().WillReturnRows(rows1)
	rows1a := sqlmock.NewRows([]string{"id", "acctid", "rolearn", "authz", "policy", "duration", "sessfmt"}).
		AddRow(test.UUID1, test.AWSAccountID1, test.RoleARN1, test.AuthzAttrib1, "", 0, "")
	ep[database.StmtKeyRoleMappingSelect].ExpectQuery().WithArgs(test.UUID1).WillReturnRows(rows1a)
	ep[database.StmtKeyRoleMappingInsert].ExpectExec().WithArgs(sqlmock.AnyArg(), test.AWSAccountID2, test.RoleARN2, test.AuthzAttrib2, "", 0, "").WillReturnResult(sqlmock.NewResult(1, 1))
	rows2 := sqlmock.NewRows([]string{"id", "acctid", "rolearn", "authz", "policy", "duration", "sessfmt"}).
		AddRow(test.UUID1, test.AWSAccountID1, test.RoleARN1, test.AuthzAttrib1, "", 0, "").
		AddRow(test.UUID2, test.AWSAccountID2, test.RoleARN2, test.AuthzAttrib2, "", 0, "")
	ep[database.StmtKeyRoleMappingSelectList].ExpectQuery().WillReturnRows(rows2)
	ep[database.StmtKeyRoleMappingDelete].ExpectExec().WithArgs(test.UUID2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyRoleMappingDelete].ExpectExec().WithArgs(test.UUID2).WillReturnResult(sqlmock.NewResult(0, 0))
	ep[database.StmtKeyRoleMappingUpdate].ExpectExec().WithArgs(test.AWSAccountID1, test.RoleARN1, test.AuthzAttrib2, "", 0, "", test.UUID1).WillReturnResult(sqlmock.NewResult(0, 1))

	for _, test := range tests {
		url := fmt.Sprintf("http://127.0.0.1:8443/%s/%s%s", APIVersion, test.Endpoint, test.Path)
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
		respStr := response.Body.String()
		// For created role mappings the uuid is dynamically generated so we need to wipe it out in the response to compare.
		if response.Code == http.StatusCreated {
			var j JSONCreatedResponse
			err = json.Unmarshal([]byte(respStr), &j)
			if err != nil {
				t.Errorf("could not unmarshal created entity response: %v", err)
			}
			j.CreatedEntity = ""
			j.Message = ""
			b, err := json.Marshal(j)
			if err != nil {
				t.Errorf("could not marshal created entity response: %v", err)
			}
			respStr = string(b)
		}
		assert.Equal(t, test.ResponseString, respStr, fmt.Sprintf("Response not as expected (%s %s)", test.Method, url))
	}
}
