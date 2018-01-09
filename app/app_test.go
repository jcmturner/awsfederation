// +build integration
// To turn on this test use -tags=integration in go test command

package app

import (
	"encoding/base64"
	"encoding/json"
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
		{"POST", httphandling.AccountStatusAPI, true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName1+"removeme"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status "+test.AccountStatusName1+"removeme"+" created.", http.StatusOK, appcodes.Info)},
		{"PUT", httphandling.AccountStatusAPI, true, "/1", fmt.Sprintf(httphandling.AccountStatusPUTTmpl, 1, test.AccountStatusName1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account status %d updated.", test.AccountStatusID1), http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", httphandling.AccountStatusAPI, true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account status with name "+test.AccountStatusName1+" already exists.", http.StatusBadRequest, appcodes.AccountStatusAlreadyExists)},
		// List 1 entry
		{"GET", httphandling.AccountStatusAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountStatuses":[{"ID":%d,"Status":"%s"}]}`, test.AccountStatusID1, test.AccountStatusName1)},
		// Get
		{"GET", httphandling.AccountStatusAPI, false, "/1", "", http.StatusOK, fmt.Sprintf(`{"ID":%d,"Status":"%s"}`, test.AccountStatusID1, test.AccountStatusName1)},
		{"POST", httphandling.AccountStatusAPI, true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, test.AccountStatusName2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status "+test.AccountStatusName2+" created.", http.StatusOK, appcodes.Info)},
		// List multiple
		{"GET", httphandling.AccountStatusAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountStatuses":[{"ID":%d,"Status":"%s"},{"ID":%d,"Status":"%s"}]}`, test.AccountStatusID1, test.AccountStatusName1, test.AccountStatusID2, test.AccountStatusName2)},
		// Method not allowed
		{"POST", httphandling.AccountStatusAPI, true, "/1", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, "somethingelse"), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"POST", httphandling.AccountStatusAPI, true, "", fmt.Sprintf(httphandling.AccountStatusPOSTTmpl, "tmpstatus"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status tmpstatus created.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountStatusAPI, true, "/3", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account status with ID 3 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountStatusAPI, true, "/3", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account status ID not found.", http.StatusNotFound, appcodes.AccountStatusUnknown)},

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
		// List multiple
		{"GET", httphandling.AccountClassAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountClasses":[{"ID":%d,"Class":"%s"},{"ID":%d,"Class":"%s"}]}`, test.AccountClassID1, test.AccountClassName1, test.AccountClassID2, test.AccountClassName2)},
		// Method not allowed
		{"POST", httphandling.AccountClassAPI, true, "/1", fmt.Sprintf(httphandling.AccountClassPOSTTmpl, "somethingelse"), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"POST", httphandling.AccountClassAPI, true, "", fmt.Sprintf(httphandling.AccountClassPOSTTmpl, "tmpclass"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account class tmpclass created.", http.StatusOK, appcodes.Info)},
		{"PUT", httphandling.AccountClassAPI, true, "/3", fmt.Sprintf(httphandling.AccountClassPUTTmpl, 3, "somethingelse"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account class %d updated.", 3), http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountClassAPI, true, "/3", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account class with ID 3 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountClassAPI, true, "/3", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account class ID not found.", http.StatusNotFound, appcodes.AccountClassUnknown)},

		// Account Type
		// Create
		{"POST", httphandling.AccountTypeAPI, true, "", fmt.Sprintf(httphandling.AccountTypePOSTTmpl, test.AccountTypeName1+"removeme", test.AccountClassID1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type "+test.AccountTypeName1+"removeme"+" created.", http.StatusOK, appcodes.Info)},
		{"PUT", httphandling.AccountTypeAPI, true, "/1", fmt.Sprintf(httphandling.AccountTypePUTTmpl, 1, test.AccountTypeName1, test.AccountClassID1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account Type %d updated.", test.AccountTypeID1), http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", httphandling.AccountTypeAPI, true, "", fmt.Sprintf(httphandling.AccountTypePOSTTmpl, test.AccountTypeName1, test.AccountClassID1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account Type with name "+test.AccountTypeName1+" already exists.", http.StatusBadRequest, appcodes.AccountTypeAlreadyExists)},
		// List 1 entry
		{"GET", httphandling.AccountTypeAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountTypes":[`+httphandling.AccountTypeGETTmpl+`]}`, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1)},
		// Get
		{"GET", httphandling.AccountTypeAPI, false, "/1", "", http.StatusOK, fmt.Sprintf(httphandling.AccountTypeGETTmpl, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1)},
		{"POST", httphandling.AccountTypeAPI, true, "", fmt.Sprintf(httphandling.AccountTypePOSTTmpl, test.AccountTypeName2, test.AccountClassID2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type "+test.AccountTypeName2+" created.", http.StatusOK, appcodes.Info)},
		// List multiple
		{"GET", httphandling.AccountTypeAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountTypes":[`+httphandling.AccountTypeGETTmpl+","+httphandling.AccountTypeGETTmpl+`]}`, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountTypeID2, test.AccountTypeName2, test.AccountClassID2)},
		// Method not allowed
		{"POST", httphandling.AccountTypeAPI, true, "/1", fmt.Sprintf(httphandling.AccountTypePOSTTmpl, "somethingelse", test.AccountClassID1), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"POST", httphandling.AccountTypeAPI, true, "", fmt.Sprintf(httphandling.AccountTypePOSTTmpl, "tmptype", test.AccountClassID1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type tmptype created.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountTypeAPI, true, "/3", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type with ID 3 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountTypeAPI, true, "/3", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account Type ID not found.", http.StatusNotFound, appcodes.AccountTypeUnknown)},

		// Federation User
		{"POST", httphandling.FederationUserAPI, true, "", fmt.Sprintf(httphandling.FederationUserPOSTTmpl, test.FedUserName1, test.FedUserArn1, test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn1+" created.", http.StatusOK, appcodes.Info)},
		{"GET", httphandling.FederationUserAPI, false, "/" + test.FedUserArn1, "", http.StatusOK, fmt.Sprintf(httphandling.FederationUserResponseTmpl, test.FedUserArn1, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial)},
		{"GET", httphandling.FederationUserAPI, false, "", "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn1 + "\"]}"},
		{"GET", httphandling.FederationUserAPI, false, fmt.Sprintf("/arn:aws:iam::%s:user", test.AWSAccountID1), "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn1 + "\"]}"},
		{"GET", httphandling.FederationUserAPI, false, "/arn:aws:iam::123456789012:user/notexist", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
		{"POST", httphandling.FederationUserAPI, true, "", fmt.Sprintf(httphandling.FederationUserPOSTTmpl, test.FedUserName1, test.FedUserArn1, test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusConflict, fmt.Sprintf(test.GenericResponseTmpl, "Federation user already exists.", http.StatusConflict, appcodes.FederationUserAlreadyExists)},
		{"POST", httphandling.FederationUserAPI, true, "/" + test.FedUserArn1, fmt.Sprintf(httphandling.FederationUserPOSTTmpl, test.FedUserName1, test.FedUserArn1, test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"POST", httphandling.FederationUserAPI, true, "", fmt.Sprintf(httphandling.FederationUserPOSTTmpl, test.FedUserName2, test.FedUserArn2, test.IAMUser2SecretAccessKey, test.IAMUser2SessionToken, test.IAMUser2Expiration, test.IAMUser2AccessKeyId, test.FedUserTTL2, test.IAMUser2MFASerial, test.IAMUser2MFASecret), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn2+" created.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.FederationUserAPI, true, "/" + test.FedUserArn2, "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn2+" deleted.", http.StatusOK, appcodes.Info)},
		{"GET", httphandling.FederationUserAPI, false, "/" + test.FedUserArn2, "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
		{"POST", httphandling.FederationUserAPI, true, "", fmt.Sprintf(httphandling.FederationUserPOSTTmpl, test.FedUserName2, test.FedUserArn2, test.IAMUser2SecretAccessKey, test.IAMUser2SessionToken, test.IAMUser2Expiration, test.IAMUser2AccessKeyId, test.FedUserTTL2, test.IAMUser2MFASerial, test.IAMUser2MFASecret), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn2+" created.", http.StatusOK, appcodes.Info)},
		{"GET", httphandling.FederationUserAPI, false, "", "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn1 + "\",\"" + test.FedUserArn2 + "\"]}"},
		{"GET", httphandling.FederationUserAPI, false, fmt.Sprintf("/arn:aws:iam::%s:user", test.AWSAccountID1), "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn1 + "\"]}"},
		{"GET", httphandling.FederationUserAPI, false, fmt.Sprintf("/arn:aws:iam::%s:user", test.AWSAccountID2), "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn2 + "\"]}"},
		{"PUT", httphandling.FederationUserAPI, true, "/arn:aws:iam::123456789012:user/blah", fmt.Sprintf(httphandling.FederationUserPOSTTmpl, "blah", "arn:aws:iam::123456789012:user/blah", test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
		{"PUT", httphandling.FederationUserAPI, true, "/" + test.FedUserArn1, fmt.Sprintf(httphandling.FederationUserPOSTTmpl, test.FedUserName1, test.FedUserArn1, test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser2AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn1+" updated.", http.StatusOK, appcodes.Info)},
		{"GET", httphandling.FederationUserAPI, false, "/" + test.FedUserArn1, "", http.StatusOK, fmt.Sprintf(httphandling.FederationUserResponseTmpl, test.FedUserArn1, test.IAMUser1Expiration, test.IAMUser2AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial)},

		// Account
		// Create
		{"POST", httphandling.AccountAPI, true, "", fmt.Sprintf(httphandling.AccountPOSTTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountStatusID1, test.FedUserArn1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account "+test.AWSAccountID1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", httphandling.AccountAPI, true, "", fmt.Sprintf(httphandling.AccountPOSTTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountStatusID1, test.FedUserArn1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "An Account with either the ID "+test.AWSAccountID1+", email "+test.AccountEmail1+" or name "+test.AccountName1+" already exists.", http.StatusBadRequest, appcodes.AccountAlreadyExists)},
		// List 1 entry
		{"GET", httphandling.AccountAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"Accounts":[`+httphandling.AccountGETTmpl+`]}`, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1)},
		// Get
		{"GET", httphandling.AccountAPI, false, "/" + test.AWSAccountID1, "", http.StatusOK, fmt.Sprintf(httphandling.AccountGETTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1)},
		{"POST", httphandling.AccountAPI, true, "", fmt.Sprintf(httphandling.AccountPOSTTmpl, test.AWSAccountID2, test.AccountEmail2, test.AccountName2, test.AccountTypeID2, test.AccountStatusID2, test.FedUserArn2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account "+test.AWSAccountID2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", httphandling.AccountAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"Accounts":[`+httphandling.AccountGETTmpl+","+httphandling.AccountGETTmpl+`]}`, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1, test.AWSAccountID2, test.AccountEmail2, test.AccountName2, test.AccountTypeID2, test.AccountTypeName2, test.AccountClassID2, test.AccountClassName2, test.AccountStatusID2, test.AccountStatusName2, test.FedUserArn2)},
		//// Method not allowed
		{"POST", httphandling.AccountAPI, true, "/" + test.AWSAccountID1, fmt.Sprintf(httphandling.AccountPOSTTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountStatusID1, test.FedUserArn1), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", httphandling.AccountAPI, true, "/" + test.AWSAccountID2, "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account with ID "+test.AWSAccountID2+" deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.AccountAPI, true, "/" + test.AWSAccountID2, "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account ID not found.", http.StatusNotFound, appcodes.AccountUnknown)},
		{"PUT", httphandling.AccountAPI, true, "/" + test.AWSAccountID1, fmt.Sprintf(httphandling.AccountPOSTTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID2, test.AccountStatusID1, test.FedUserArn1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account %s updated.", test.AWSAccountID1), http.StatusOK, appcodes.Info)},
		{"POST", httphandling.AccountAPI, true, "", fmt.Sprintf(httphandling.AccountPOSTTmpl, test.AWSAccountID2, test.AccountEmail2, test.AccountName2, test.AccountTypeID2, test.AccountStatusID2, test.FedUserArn2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account "+test.AWSAccountID2+" created.", http.StatusOK, appcodes.Info)},

		// Role Mapping
		//{"POST", httphandling.RoleMappingAPI, true, "", fmt.Sprintf(httphandling.RoleMappingPOSTTmpl, test.RoleARN1, test.AuthzAttrib1), http.StatusCreated, fmt.Sprintf(test.CreatedResponseTmpl, "", "")},
		//// List 1 entry
		//{"GET", httphandling.RoleMappingAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"RoleMappings":[`+httphandling.RoleMappingGETTmpl+`]}`, test.UUID1, test.RoleARN1, test.AuthzAttrib1, test.AWSAccountID1)},
		//// Get
		//{"GET", httphandling.RoleMappingAPI, false, "/" + test.UUID1, "", http.StatusOK, fmt.Sprintf(httphandling.RoleMappingGETTmpl, test.UUID1, test.RoleARN1, test.AuthzAttrib1, test.AWSAccountID1)},
		//{"POST", httphandling.RoleMappingAPI, true, "", fmt.Sprintf(httphandling.RoleMappingPOSTTmpl, test.RoleARN2, test.AuthzAttrib2), http.StatusCreated, fmt.Sprintf(test.CreatedResponseTmpl, "", "")},
		//// List multiple
		//{"GET", httphandling.RoleMappingAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"RoleMappings":[`+httphandling.RoleMappingGETTmpl+`,`+httphandling.RoleMappingGETTmpl+`]}`, test.UUID1, test.RoleARN1, test.AuthzAttrib1, test.AWSAccountID1, test.UUID2, test.RoleARN2, test.AuthzAttrib2, test.AWSAccountID2)},
		//// Method not allowed
		//{"POST", httphandling.RoleMappingAPI, true, "/" + test.UUID1, fmt.Sprintf(httphandling.RoleMappingPOSTTmpl, test.RoleARN1, test.AuthzAttrib2), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		//{"DELETE", httphandling.RoleMappingAPI, true, "/" + test.UUID2, "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Role Mapping with ID "+test.UUID2+" deleted.", http.StatusOK, appcodes.Info)},
		//{"DELETE", httphandling.RoleMappingAPI, true, "/" + test.UUID2, "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Role Mapping ID not found.", http.StatusNotFound, appcodes.RoleMappingUnknown)},
		//{"PUT", httphandling.RoleMappingAPI, true, "/" + test.UUID1, fmt.Sprintf(httphandling.RoleMappingPUTTmpl, test.UUID1, test.RoleARN1, test.AuthzAttrib2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Role Mapping %s updated.", test.UUID1), http.StatusOK, appcodes.Info)},
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
		bodyBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("error getting response body from %s: %v", url, err)
		}
		defer response.Body.Close()
		respStr := string(bodyBytes)
		assert.Equal(t, test.HttpCode, response.StatusCode, fmt.Sprintf("Expected HTTP code: %d got: %d (%s %s)", test.HttpCode, response.StatusCode, test.Method, url))
		assert.Equal(t, test.ResponseString, respStr, fmt.Sprintf("Response not as expected (%s %s)", test.Method, url))
	}
}

func TestRoleMapping(t *testing.T) {
	url := fmt.Sprintf("http://127.0.0.1:8443/%s/%s", httphandling.APIVersion, httphandling.RoleMappingAPI)
	request1, err := http.NewRequest("POST", url, strings.NewReader(fmt.Sprintf(httphandling.RoleMappingPOSTTmpl, test.RoleARN1, test.AuthzAttrib1)))
	if err != nil {
		t.Fatalf("error building request: %v", err)
	}
	request1.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser@TESTING:"+config.MockStaticSecret)))
	request2, err := http.NewRequest("POST", url, strings.NewReader(fmt.Sprintf(httphandling.RoleMappingPOSTTmpl, test.RoleARN2, test.AuthzAttrib2)))
	if err != nil {
		t.Fatalf("error building request: %v", err)
	}
	request2.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser@TESTING:"+config.MockStaticSecret)))
	rs := []*http.Request{request1, request2}
	var rm []httphandling.JSONCreatedResponse
	for _, r := range rs {
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatalf("error performing request: %v", err)
		}
		bodyBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("error getting response body from %s: %v", url, err)
		}
		defer response.Body.Close()
		var j httphandling.JSONCreatedResponse
		err = json.Unmarshal(bodyBytes, &j)
		if err != nil {
			t.Fatalf("error unmarshalling response: %v")
		}
		rm = append(rm, j)
		assert.Equal(t, http.StatusCreated, j.HTTPCode, "Status code not as expected")
		assert.Equal(t, appcodes.Info, j.ApplicationCode, "App code not as expected")
	}
	uuid1 := rm[0].CreatedEntity
	uuid2 := rm[1].CreatedEntity

	var tests = []struct {
		Method         string
		Endpoint       string
		AuthRequired   bool
		Path           string
		PostPayload    string
		HttpCode       int
		ResponseString string
	}{
		// Role Mapping
		// Get
		{"GET", httphandling.RoleMappingAPI, false, "/" + uuid1, "", http.StatusOK, fmt.Sprintf(httphandling.RoleMappingGETTmpl, uuid1, test.RoleARN1, test.AuthzAttrib1, test.AWSAccountID1)},
		// List
		{"GET", httphandling.RoleMappingAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"RoleMappings":[`+httphandling.RoleMappingGETTmpl+`,`+httphandling.RoleMappingGETTmpl+`]}`, uuid1, test.RoleARN1, test.AuthzAttrib1, test.AWSAccountID1, uuid2, test.RoleARN2, test.AuthzAttrib2, test.AWSAccountID2)},
		// Method not allowed
		{"DELETE", httphandling.RoleMappingAPI, true, "/" + uuid2, "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Role Mapping with ID "+uuid2+" deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", httphandling.RoleMappingAPI, true, "/" + uuid2, "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Role Mapping ID not found.", http.StatusNotFound, appcodes.RoleMappingUnknown)},
		{"PUT", httphandling.RoleMappingAPI, true, "/" + uuid1, fmt.Sprintf(httphandling.RoleMappingPUTTmpl, uuid1, test.RoleARN1, test.AuthzAttrib2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Role Mapping %s updated.", uuid1), http.StatusOK, appcodes.Info)},
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
		bodyBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("error getting response body from %s: %v", url, err)
		}
		defer response.Body.Close()
		respStr := string(bodyBytes)
		assert.Equal(t, test.HttpCode, response.StatusCode, fmt.Sprintf("Expected HTTP code: %d got: %d (%s %s)", test.HttpCode, response.StatusCode, test.Method, url))
		assert.Equal(t, test.ResponseString, respStr, fmt.Sprintf("Response not as expected (%s %s)", test.Method, url))
	}
}
