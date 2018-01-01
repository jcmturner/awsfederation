package database

const (
	StmtKeyAcctTypeSelectList = 40
	QueryAcctTypeSelectList   = "SELECT id, type, class_id FROM accountType"
	StmtKeyAcctTypeSelect     = 41
	QueryAcctTypeSelect       = "SELECT id, type, class_id  FROM accountType WHERE id = ?"
	StmtKeyAcctTypeInsert     = 42
	QueryAcctTypeInsert       = "INSERT IGNORE INTO accountType (type, class_id) VALUES (?, ?)"
	StmtKeyAcctTypeDelete     = 43
	QueryAcctTypeDelete       = "DELETE FROM accountType WHERE id = ?"
	StmtKeyAcctTypeUpdate     = 44
	QueryAcctTypeUpdate       = "UPDATE accountType SET type = ?, class_id = ? WHERE id = ?"
)

type accountType struct{}

func (p *accountType) stmts() []Statement {
	return []Statement{
		{
			ID:    StmtKeyAcctTypeSelect,
			Query: QueryAcctTypeSelect,
		},
		{
			ID:    StmtKeyAcctTypeSelectList,
			Query: QueryAcctTypeSelectList,
		},
		{
			ID:    StmtKeyAcctTypeInsert,
			Query: QueryAcctTypeInsert,
		},
		{
			ID:    StmtKeyAcctTypeDelete,
			Query: QueryAcctTypeDelete,
		},
		{
			ID:    StmtKeyAcctTypeUpdate,
			Query: QueryAcctTypeUpdate,
		},
	}
}
