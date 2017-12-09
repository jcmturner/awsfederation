package database

const (
	StmtKeyFedUserSelect = 3
	QueryFedUserSelect   = "SELECT name, ttl FROM federationUser WHERE arn = ?"
	StmtKeyFedUserInsert = 4
	QueryFedUserInsert   = "INSERT IGNORE INTO federationUser (arn, name, ttl) VALUES (?, ?, ?)"
	StmtKeyFedUserDelete = 5
	QueryFedUserDelete   = "DELETE FROM federationUser WHERE arn = ?"
)

type federationUser struct{}

func (p *federationUser) stmts() []Statement {
	return []Statement{
		{
			ID:    StmtKeyFedUserSelect,
			Query: QueryFedUserSelect,
		},
		{
			ID:    StmtKeyFedUserInsert,
			Query: QueryFedUserInsert,
		},
		{
			ID:    StmtKeyFedUserDelete,
			Query: QueryFedUserDelete,
		},
	}
}
