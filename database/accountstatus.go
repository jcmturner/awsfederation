package database

const (
	StmtKeyAcctStatusSelectList = 6
	QueryAcctStatusSelectList   = "SELECT id, status FROM accountStatus"
	StmtKeyAcctStatusSelect     = 7
	QueryAcctStatusSelect       = "SELECT id, status FROM accountStatus WHERE id = ?"
	StmtKeyAcctStatusInsert     = 8
	QueryAcctStatusInsert       = "INSERT IGNORE INTO accountStatus (status) VALUES (?)"
	StmtKeyAcctStatusDelete     = 9
	QueryAcctStatusDelete       = "DELETE FROM accountStatus WHERE id = ?"
	StmtKeyAcctStatusUpdate     = 10
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
