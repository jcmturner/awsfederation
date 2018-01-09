package database

const (
	StmtKeyAcctSelectList = 10
	QueryAcctSelectList   = "SELECT account.id, email, name, " +
		"accountType_id, accountType.type, " +
		"accountClass.id, accountClass.class, " +
		"accountStatus_id, accountStatus.status, " +
		"federationUser_arn " +
		"FROM account " +
		"JOIN accountType ON account.accountType_id = accountType.id " +
		"JOIN accountClass ON accountType.class_id = accountClass.id " +
		"JOIN accountStatus ON account.accountStatus_id = accountStatus.id " +
		"ORDER BY account.id ASC"
	StmtKeyAcctSelect = 11
	QueryAcctSelect   = "SELECT account.id, email, name, " +
		"accountType_id, accountType.type, " +
		"accountClass.id, accountClass.class, " +
		"accountStatus_id, accountStatus.status, " +
		"federationUser_arn " +
		"FROM account " +
		"JOIN accountType ON account.accountType_id = accountType.id " +
		"JOIN accountClass ON accountType.class_id = accountClass.id " +
		"JOIN accountStatus ON account.accountStatus_id = accountStatus.id " +
		"WHERE account.id = ?"
	StmtKeyAcctInsert      = 12
	QueryAcctInsert        = "INSERT IGNORE INTO account (id, email, name, accountType_id, accountStatus_id, federationUser_arn) VALUES (?, ?, ?, ?, ?, ?)"
	StmtKeyAcctDelete      = 13
	QueryAcctDelete        = "DELETE FROM account WHERE id = ?"
	StmtKeyAcctUpdate      = 14
	QueryAcctUpdate        = "UPDATE account SET email = ?, name = ?, accountType_id = ?, accountStatus_id = ?, federationUser_arn = ? WHERE id = ?"
	StmtKeyAcctCheckUnique = 15
	QueryAcctCheckUnique   = "SELECT account.id FROM account WHERE account.id = ? OR email = ? OR name = ?"
)

type account struct{}

func (p *account) stmts() []Statement {
	return []Statement{
		{
			ID:    StmtKeyAcctSelect,
			Query: QueryAcctSelect,
		},
		{
			ID:    StmtKeyAcctSelectList,
			Query: QueryAcctSelectList,
		},
		{
			ID:    StmtKeyAcctInsert,
			Query: QueryAcctInsert,
		},
		{
			ID:    StmtKeyAcctDelete,
			Query: QueryAcctDelete,
		},
		{
			ID:    StmtKeyAcctUpdate,
			Query: QueryAcctUpdate,
		},
		{
			ID:    StmtKeyAcctCheckUnique,
			Query: QueryAcctCheckUnique,
		},
	}
}
