package database

const (
	StmtKeyAuthzCheck        = 50
	QueryAuthzCheck          = "SELECT authz_attrib FROM roleMapping WHERE id =?"
	StmtKeyRoleMappingLookup = 51
	QueryRoleMappingLookup   = "SELECT role_arn, federationUser.arn, duration, policy, session_name_format " +
		"FROM roleMapping " +
		"JOIN account ON roleMapping.account_id = account.id " +
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
