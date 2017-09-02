package database

import (
	"database/sql"
	"gopkg.in/DATA-DOG/go-sqlmock.v1"
	"regexp"
	"testing"
)

func Mock(t *testing.T) (*sql.DB, sqlmock.Sqlmock, map[int]*sqlmock.ExpectedPrepare, *StmtMap) {
	// Database mock and prepare statements
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error when opening a mock database connection: %v", err)
	}

	ep := make(map[int]*sqlmock.ExpectedPrepare)
	for _, stmt := range Statements() {
		ep[stmt.ID] = mock.ExpectPrepare(regexp.QuoteMeta(stmt.Query))
	}
	stmtMap, err := NewStmtMap(db)
	if err != nil {
		t.Fatalf("Error creating statement map: %v", err)
	}
	return db, mock, ep, stmtMap
}
