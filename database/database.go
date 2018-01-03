package database

import (
	"database/sql"
	"fmt"
)

type StmtMap map[int]*sql.Stmt

type Statement struct {
	ID    int
	Query string
}

type stmtProvider interface {
	stmts() []Statement
}

func NewStmtMap(db *sql.DB) (*StmtMap, error) {
	stmtMap := make(StmtMap)
	err := addStmt(&stmtMap, Statements(), db)
	return &stmtMap, err
}

func Statements() []Statement {
	ps := []stmtProvider{
		new(assumeRole),
		new(federationUser),
		new(accountClass),
		new(accountType),
		new(accountStatus),
		new(roleMapping),
		new(account),
	}
	var s []Statement
	for _, p := range ps {
		s = append(s, p.stmts()...)
	}
	return s
}

func addStmt(stmtMap *StmtMap, stmts []Statement, db *sql.DB) error {
	for _, stmt := range stmts {
		s, err := db.Prepare(stmt.Query)
		if err != nil {
			return fmt.Errorf("Error preparing statement ID %d: %v", stmt.ID, err)
		}
		(*stmtMap)[stmt.ID] = s
	}
	return nil
}
