package database

const (
	StmtKeyAcctStatusSelectList = 30
	QueryAcctStatusSelectList   = "SELECT id, status FROM accountStatus ORDER BY id ASC"
	StmtKeyAcctStatusSelect     = 31
	QueryAcctStatusSelect       = "SELECT id, status FROM accountStatus WHERE id = ?"
	StmtKeyAcctStatusByName     = 32
	QueryAcctStatusByName       = "SELECT id FROM accountStatus WHERE status = ?"
	StmtKeyAcctStatusInsert     = 33
	QueryAcctStatusInsert       = "INSERT IGNORE INTO accountStatus (status) VALUES (?)"
	StmtKeyAcctStatusDelete     = 34
	QueryAcctStatusDelete       = "DELETE FROM accountStatus WHERE id = ?"
	StmtKeyAcctStatusUpdate     = 35
	QueryAcctStatusUpdate       = "UPDATE accountStatus SET status = ? WHERE id = ?"
)

type accountStatus struct{}

func (p *accountStatus) stmts() []Statement {
	return []Statement{
		{
			ID:    StmtKeyAcctStatusSelect,
			Query: QueryAcctStatusSelect,
		},
		{
			ID:    StmtKeyAcctStatusSelectList,
			Query: QueryAcctStatusSelectList,
		},
		{
			ID:    StmtKeyAcctStatusByName,
			Query: QueryAcctStatusByName,
		},
		{
			ID:    StmtKeyAcctStatusInsert,
			Query: QueryAcctStatusInsert,
		},
		{
			ID:    StmtKeyAcctStatusDelete,
			Query: QueryAcctStatusDelete,
		},
		{
			ID:    StmtKeyAcctStatusUpdate,
			Query: QueryAcctStatusUpdate,
		},
	}
}
