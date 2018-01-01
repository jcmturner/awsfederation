package database

const (
	StmtKeyAcctStatusSelectList = 30
	QueryAcctStatusSelectList   = "SELECT id, status FROM accountStatus"
	StmtKeyAcctStatusSelect     = 31
	QueryAcctStatusSelect       = "SELECT id, status FROM accountStatus WHERE id = ?"
	StmtKeyAcctStatusInsert     = 32
	QueryAcctStatusInsert       = "INSERT IGNORE INTO accountStatus (status) VALUES (?)"
	StmtKeyAcctStatusDelete     = 33
	QueryAcctStatusDelete       = "DELETE FROM accountStatus WHERE id = ?"
	StmtKeyAcctStatusUpdate     = 34
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
