package database

const (
	StmtKeyAcctClassSelectList = 20
	QueryAcctClassSelectList   = "SELECT id, class FROM accountClass"
	StmtKeyAcctClassSelect     = 21
	QueryAcctClassSelect       = "SELECT id, class FROM accountClass WHERE id = ?"
	StmtKeyAcctClassInsert     = 22
	QueryAcctClassInsert       = "INSERT IGNORE INTO accountClass (class) VALUES (?)"
	StmtKeyAcctClassDelete     = 23
	QueryAcctClassDelete       = "DELETE FROM accountClass WHERE id = ?"
	StmtKeyAcctClassUpdate     = 24
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
