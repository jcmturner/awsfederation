package database

import (
	"database/sql"
	"fmt"
)

type Statement struct {
	ID    int
	Query string
}

type StmtMap map[int]*sql.Stmt

func NewStmtMap(db *sql.DB) (*StmtMap, error) {
	stmtMap := make(StmtMap)
	err := addStmt(&stmtMap, Statements(), db)
	return &stmtMap, err
}

func Statements() []Statement {
	fs := []func() []Statement{
		getAssumeRoleStmts,
		getFederationUserStmts,
	}
	var s []Statement
	for _, f := range fs {
		s = append(s, f()...)
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
