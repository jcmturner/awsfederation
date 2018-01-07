package database

const (
	StmtKeyAcctClassSelectList = 20
	QueryAcctClassSelectList   = "SELECT id, class FROM accountClass"
	StmtKeyAcctClassSelect     = 21
	QueryAcctClassSelect       = "SELECT id, class FROM accountClass WHERE id = ?"
	StmtKeyAcctClassByName     = 22
	QueryAcctClassByName       = "SELECT id FROM accountClass WHERE class = ?"
	StmtKeyAcctClassInsert     = 23
	QueryAcctClassInsert       = "INSERT IGNORE INTO accountClass (class) VALUES (?)"
	StmtKeyAcctClassDelete     = 24
	QueryAcctClassDelete       = "DELETE FROM accountClass WHERE id = ?"
	StmtKeyAcctClassUpdate     = 25
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
			ID:    StmtKeyAcctClassByName,
			Query: QueryAcctClassByName,
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
