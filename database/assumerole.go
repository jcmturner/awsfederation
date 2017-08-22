package database

const (
	StmtKeyAuthzCheck        = 1
	QueryAuthzCheck          = "SELECT authzAttribute FROM roleMapping WHERE id =?"
	StmtKeyRoleMappingLookup = 2
	QueryRoleMappingLookup   = "SELECT role.arn, federationUser.arn, duration, policy, roleSessionNameFormat " +
		"FROM roleMapping " +
		"JOIN role ON roleMapping.role_arn = role.arn " +
		"JOIN account ON role.account_id = account.id " +
		"JOIN federationUser ON account.federationUser_arn = federationUser.arn " +
		"WHERE roleMapping.id = ?"
)

type assumeRole struct{}

func (a assumeRole) stmts() []Statement {
	return []Statement{
		{
			ID:    StmtKeyAuthzCheck,
			Query: QueryAuthzCheck,
		},
		{
			ID:    StmtKeyRoleMappingLookup,
			Query: QueryRoleMappingLookup,
		},
	}
}
