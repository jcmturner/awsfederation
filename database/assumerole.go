package database

const (
	StmtKeyAuthzCheck = 1
	queryAuthzCheck = "SELECT AuthzAttrib FROM RoleMapping WHERE id =?"
	StmtKeyRoleMappingLookup = 2
	queryRoleMappingLookup = "SELECT RoleArn, FederationUser, SessionDuration, Policy, RoleSessionName FROM RoleMapping WHERE id = ?"
)

func getAssumeRoleStmts() []Statement {
	return []Statement {
		{
			ID: StmtKeyAuthzCheck,
			Query: queryAuthzCheck,
		},
		{
			ID: StmtKeyRoleMappingLookup,
			Query: queryRoleMappingLookup,
		},
	}
}