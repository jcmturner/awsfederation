package database

const (
	StmtKeyAcctClassSelectList = 6
	QueryAcctClassSelectList   = "SELECT id, class FROM accountClass"
	StmtKeyAcctClassSelect     = 7
	QueryAcctClassSelect       = "SELECT id, class FROM accountClass WHERE id = ?"
	StmtKeyAcctClassInsert     = 8
	QueryAcctClassInsert       = "INSERT IGNORE INTO accountClass (class) VALUES (?)"
	StmtKeyAcctClassDelete     = 9
	QueryAcctClassDelete       = "DELETE FROM accountClass WHERE arn = ?"
	StmtKeyAcctClassUpdate     = 10
	QueryAcctClassUpdate       = "UPDATE accountClass SET class = ? WHERE id = ?"
)

type accountClass struct{}

func (p *accountClass) stmts() []Statement {
	return []Statement{
		{
			ID:    StmtKeyAcctClassSelect,
			Query: QueryAcctClassSelect,
		},
		{
			ID:    StmtKeyAcctClassSelectList,
			Query: QueryAcctClassSelectList,
		},
		{
			ID:    StmtKeyAcctClassInsert,
			Query: QueryAcctClassInsert,
		},
		{
			ID:    StmtKeyAcctClassDelete,
			Query: QueryAcctClassDelete,
		},
		{
			ID:    StmtKeyAcctClassUpdate,
			Query: QueryAcctClassUpdate,
		},
	}
}
