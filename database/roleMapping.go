package database

const (
	StmtKeyRoleMappingSelectList = 70
	QueryRoleMappingSelectList   = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping"
	StmtKeyRoleMappingSelect     = 71
	QueryRoleMappingSelect       = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping WHERE id = ?"
	StmtKeyRoleMappingByAuthz    = 72
	QueryRoleMappingByAuthz      = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping WHERE authz_attrib IN (?)"
	StmtKeyRoleMappingByARN      = 73
	QueryRoleMappingByARN        = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping WHERE role_arn IN (?)"
	StmtKeyRoleMappingByAcct     = 74
	QueryRoleMappingByAcct       = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping WHERE account_id IN (?)"
	StmtKeyRoleMappingInsert     = 75
	QueryRoleMappingInsert       = "INSERT INTO roleMapping (id, account_id, role_arn, authz_attrib, policy, duration, session_name_format) VALUES (?, ?, ?, ?, ?, ?, ?)"
	StmtKeyRoleMappingDelete     = 76
	QueryRoleMappingDelete       = "DELETE FROM roleMapping WHERE id = ?"
	StmtKeyRoleMappingIDExists   = 77
	QueryRoleMappingIDExists     = "SELECT 1 FROM roleMapping WHERE id = ? LIMIT 1"
	StmtKeyRoleMappingUpdate     = 78
	QueryRoleMappingUpdate       = "UPDATE roleMapping SET account_id = ?, role_arn = ?, authz_attrib = ?, policy = ?, duration = ?, session_name_format = ? WHERE id = ?"
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
			ID:    StmtKeyRoleMappingUpdate,
			Query: QueryRoleMappingUpdate,
		},
	}
}
