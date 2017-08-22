package database

const (
	StmtKeyFedUserInsert = 3
	QueryFedUserInsert   = "INSERT IGNORE INTO federationUser VALUES (?)"
	StmtKeyFedUserDelete = 4
	QueryFedUserDelete   = "DELETE FROM federationUser WHERE arn = ?"
)

type federationUser struct{}

func (p *federationUser) stmts() []Statement {
	return []Statement{
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
