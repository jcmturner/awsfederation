package database

const (
	StmtKeyRoleSelectList = 21
	QueryRoleSelectList   = "SELECT arn, account_id FROM role"
	StmtKeyRoleSelect     = 22
	QueryRoleSelect       = "SELECT arn, account_id  FROM role WHERE arn = ?"
	StmtKeyRoleByAcct     = 23
	QueryRoleByAcct       = "SELECT arn, account_id  FROM role WHERE account_id IN (?)"
	StmtKeyRoleInsert     = 24
	QueryRoleInsert       = "INSERT IGNORE INTO role (arn, account_id) VALUES (?, ?)"
	StmtKeyRoleDelete     = 25
	QueryRoleDelete       = "DELETE FROM role WHERE arn = ?"
)

type role struct{}

func (p *role) stmts() []Statement {
	return []Statement{
		{
			ID:    StmtKeyRoleSelect,
			Query: QueryRoleSelect,
		},
		{
			ID:    StmtKeyRoleSelectList,
			Query: QueryRoleSelectList,
		},
		{
			ID:    StmtKeyRoleByAcct,
			Query: QueryRoleByAcct,
		},
		{
			ID:    StmtKeyRoleInsert,
			Query: QueryRoleInsert,
		},
		{
			ID:    StmtKeyRoleDelete,
			Query: QueryRoleDelete,
		},
	}
}
