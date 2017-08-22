package assumerole

import (
	"github.com/hashicorp/go-uuid"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/goidentity"
	"github.com/stretchr/testify/assert"
	"gopkg.in/DATA-DOG/go-sqlmock.v1"
	"regexp"
	"testing"
)

const (
	authzAttrib = "attrib1"
)

func TestAuthorize(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	ep := make(map[int]*sqlmock.ExpectedPrepare)
	for _, stmt := range database.Statements() {
		ep[stmt.ID] = mock.ExpectPrepare(regexp.QuoteMeta(stmt.Query))
	}

	stmtMap, err := database.NewStmtMap(db)
	if err != nil {
		t.Fatalf("Error creating statement map: %v", err)
	}

	roleMappingID, _ := uuid.GenerateUUID()
	rows := sqlmock.NewRows([]string{"authzAttribute"}).
		AddRow(authzAttrib).
		AddRow("otherAttrib")

	user := goidentity.NewUser("testuser")
	user.AddAuthzAttribute(authzAttrib)

	ep[database.StmtKeyAuthzCheck].ExpectQuery().WithArgs(roleMappingID).WillReturnRows(rows)
	authz, err := Authorize(&user, roleMappingID, *stmtMap)
	if err != nil {
		t.Fatalf("Error in authorization: %v", err)
	}
	assert.True(t, authz, "User should be authorized but is not.")

	user.DisableAuthzAttribute(authzAttrib)
	ep[database.StmtKeyAuthzCheck].ExpectQuery().WithArgs(roleMappingID).WillReturnRows(rows)
	authz, err = Authorize(&user, roleMappingID, *stmtMap)
	if err != nil {
		t.Fatalf("Error in authorization: %v", err)
	}
	assert.False(t, authz, "User should be not be authorized with a disabled attribute")

	user.EnableAuthzAttribute(authzAttrib)
	user.RemoveAuthzAttribute(authzAttrib)
	ep[database.StmtKeyAuthzCheck].ExpectQuery().WithArgs(roleMappingID).WillReturnRows(rows)
	authz, err = Authorize(&user, roleMappingID, *stmtMap)
	if err != nil {
		t.Fatalf("Error in authorization: %v", err)
	}
	assert.False(t, authz, "User should be not be authorized without attribute")
}

func TestRoleMappingLookup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	roleMappingID, _ := uuid.GenerateUUID()

	testRoleArn := "arn:aws:iam::201345678912:role/role-name"
	testFedUserArn := "arn:aws:iam::012345678912:user/feduser"
	testDuration := int64(60)
	testPolicy := "{test policy string}"
	testRoleSessFmt := "${domain}/${username}"

	roleMappingLookupRows := sqlmock.NewRows([]string{"role.arn", "federationUser.arn", "duration", "policy", "roleSessionNameFormat"}).
		AddRow(testRoleArn, testFedUserArn, testDuration, testPolicy, testRoleSessFmt)

	ep := make(map[int]*sqlmock.ExpectedPrepare)
	for _, stmt := range database.Statements() {
		ep[stmt.ID] = mock.ExpectPrepare(regexp.QuoteMeta(stmt.Query))
	}

	stmtMap, err := database.NewStmtMap(db)
	if err != nil {
		t.Fatalf("Error creating statement map: %v", err)
	}

	ep[database.StmtKeyRoleMappingLookup].ExpectQuery().WithArgs(roleMappingID).WillReturnRows(roleMappingLookupRows)
	role, fuStr, duration, policyStr, roleSessionNameFmt, err := RoleMappingLookup(roleMappingID, *stmtMap)
	if err != nil {
		t.Fatalf("Error from RoleMappingLookup: %v", err)
	}
	assert.Equal(t, testRoleArn, role, "Role arn returned from db query not as expected")
	assert.Equal(t, testFedUserArn, fuStr, "Federation user arn returned from db query not as expected")
	assert.Equal(t, testDuration, duration, "Duraction returned from db query not as expected")
	assert.Equal(t, testPolicy, policyStr, "Policy override returned from db query not as expected")
	assert.Equal(t, testRoleSessFmt, roleSessionNameFmt, "RoleSessionFormat returned from db query not as expected")
}

func TestRoleSessionNamef(t *testing.T) {
	testFmt := "${displayname}:${domain}/${username}-${human}"
	u := goidentity.NewUser("testUserName")
	u.SetDisplayName("testDisplay")
	u.SetDomain("mydomain")
	u.SetHuman(true)
	assert.Equal(t, "testDisplay:mydomain/testUserName-true", roleSessionNamef(testFmt, &u), "Role session nam eofmrating not correct")
}
