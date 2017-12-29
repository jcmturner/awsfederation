package database

const (
	StmtKeyRoleMappingSelectList = 26
	QueryRoleMappingSelectList   = "SELECT id, authz_attrib, policy, duration, session_name_format, role_arn, role.account_id FROM roleMapping JOIN role ON roleMapping.role_arn = role.arn"
	StmtKeyRoleMappingSelect     = 27
	QueryRoleMappingSelect       = "SELECT id, authz_attrib, policy, duration, session_name_format, role_arn, role.account_id FROM roleMapping JOIN role ON roleMapping.role_arn = role.arn WHERE id = ?"
	StmtKeyRoleMappingByAuthz    = 28
	QueryRoleMappingByAuthz      = "SELECT id, authz_attrib, policy, duration, session_name_format, role_arn, role.account_id FROM roleMapping JOIN role ON roleMapping.role_arn = role.arn WHERE authz_attrib IN (?)"
	StmtKeyRoleMappingByARN      = 29
	QueryRoleMappingByARN        = "SELECT id, authz_attrib, policy, duration, session_name_format, role_arn, role.account_id FROM roleMapping JOIN role ON roleMapping.role_arn = role.arn WHERE role_arn IN (?)"
	StmtKeyRoleMappingByAcct     = 30
	QueryRoleMappingByAcct       = "SELECT id, authz_attrib, policy, duration, session_name_format, role_arn, role.account_id FROM roleMapping JOIN role ON roleMapping.role_arn = role.arn WHERE role.account_id IN (?)"
	StmtKeyRoleMappingInsert     = 31
	QueryRoleMappingInsert       = "INSERT INTO roleMapping (id, authz_attrib, policy, duration, session_name_format, role_arn) VALUES (?, ?, ?, ?, ?, ?)"
	StmtKeyRoleMappingDelete     = 32
	QueryRoleMappingDelete       = "DELETE FROM roleMapping WHERE id = ?"
	StmtKeyRoleMappingIDExists   = 33
	QueryRoleMappingIDExists     = "SELECT 1 FROM roleMapping WHERE id = ? LIMIT 1"
	StmtKeyRoleMappingExists     = 34
	QueryRoleMappingExists       = "SELECT 1 FROM roleMapping WHERE authz_attrib = ? AND role_arn = ? LIMIT 1"
	StmtKeyRoleMappingUpdate     = 35
	QueryRoleMappingUpdate       = "UPDATE roleMapping SET authz_attrib = ?, policy = ?, duration = ?, session_name_format = ?, role_arn = ? WHERE id = ?"
)

type roleMapping struct{}

func (p *roleMapping) stmts() []Statement {
	return []Statement{
		{
			ID:    StmtKeyRoleMappingSelect,
			Query: QueryRoleMappingSelect,
		},
		{
			ID:    StmtKeyRoleMappingSelectList,
			Query: QueryRoleMappingSelectList,
		},
		{
			ID:    StmtKeyRoleMappingByAuthz,
			Query: QueryRoleMappingByAuthz,
		},
		{
			ID:    StmtKeyRoleMappingByARN,
			Query: QueryRoleMappingByARN,
		},
		{
			ID:    StmtKeyRoleMappingByAcct,
			Query: QueryRoleMappingByAcct,
		},
		{
			ID:    StmtKeyRoleMappingInsert,
			Query: QueryRoleMappingInsert,
		},
		{
			ID:    StmtKeyRoleMappingDelete,
			Query: QueryRoleMappingDelete,
		},
		{
			ID:    StmtKeyRoleMappingIDExists,
			Query: QueryRoleMappingIDExists,
		},
		{
			ID:    StmtKeyRoleMappingExists,
			Query: QueryRoleMappingExists,
		},
		{
			ID:    StmtKeyRoleMappingUpdate,
			Query: QueryRoleMappingUpdate,
		},
	}
}
