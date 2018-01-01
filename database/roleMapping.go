package database

const (
	StmtKeyRoleMappingSelectList = 26
	QueryRoleMappingSelectList   = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping"
	StmtKeyRoleMappingSelect     = 27
	QueryRoleMappingSelect       = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping WHERE id = ?"
	StmtKeyRoleMappingByAuthz    = 28
	QueryRoleMappingByAuthz      = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping WHERE authz_attrib IN (?)"
	StmtKeyRoleMappingByARN      = 29
	QueryRoleMappingByARN        = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping WHERE role_arn IN (?)"
	StmtKeyRoleMappingByAcct     = 30
	QueryRoleMappingByAcct       = "SELECT id, account_id, role_arn, authz_attrib, policy, duration, session_name_format FROM roleMapping WHERE account_id IN (?)"
	StmtKeyRoleMappingInsert     = 31
	QueryRoleMappingInsert       = "INSERT INTO roleMapping (id, account_id, role_arn, authz_attrib, policy, duration, session_name_format) VALUES (?, ?, ?, ?, ?, ?, ?)"
	StmtKeyRoleMappingDelete     = 32
	QueryRoleMappingDelete       = "DELETE FROM roleMapping WHERE id = ?"
	StmtKeyRoleMappingIDExists   = 33
	QueryRoleMappingIDExists     = "SELECT 1 FROM roleMapping WHERE id = ? LIMIT 1"
	StmtKeyRoleMappingUpdate     = 34
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
