package database

const (
	StmtKeyAuthzCheck        = 50
	QueryAuthzCheck          = "SELECT authz_attrib FROM roleMapping WHERE id =?"
	StmtKeyRoleMappingLookup = 51
	QueryRoleMappingLookup   = "SELECT role.arn, federationUser.arn, duration, policy, session_name_format " +
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
