package database

const (
	StmtKeyAcctTypeSelectList = 40
	QueryAcctTypeSelectList   = "SELECT id, type, class_id FROM accountType ORDER BY id ASC"
	StmtKeyAcctTypeSelect     = 41
	QueryAcctTypeSelect       = "SELECT id, type, class_id FROM accountType WHERE id = ?"
	StmtKeyAcctTypeByName     = 42
	QueryAcctTypeByName       = "SELECT id FROM accountType WHERE type = ?"
	StmtKeyAcctTypeInsert     = 43
	QueryAcctTypeInsert       = "INSERT IGNORE INTO accountType (type, class_id) VALUES (?, ?)"
	StmtKeyAcctTypeDelete     = 44
	QueryAcctTypeDelete       = "DELETE FROM accountType WHERE id = ?"
	StmtKeyAcctTypeUpdate     = 45
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
			ID:    StmtKeyAcctTypeByName,
			Query: QueryAcctTypeByName,
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
