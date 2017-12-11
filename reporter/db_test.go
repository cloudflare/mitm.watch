package main

import (
	"database/sql"
	"net"
	"testing"
)

func testDB() *sql.DB {
	db, err := sql.Open("postgres", "sslmode=disable")
	if err != nil {
		panic(err)
	}
	if err = db.Ping(); err != nil {
		panic(err)
	}
	return db
}

func TestTestCreate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests")
		return
	}
	db := testDB()
	tx, err := db.Begin()
	if err != nil {
		t.Errorf("Transaction start failed: %v", err)
		return
	}
	m := &Test{
		ClientIP: net.ParseIP("::"),
	}

	// test
	err = m.Create(tx)
	if err != nil {
		t.Errorf("Query failed: %v", err)
	}

	// subtests
	for i := 1; i <= 6; i++ {
		subtest := &Subtest{
			TestID: m.ID,
			Number: i,
		}
		err = subtest.Create(tx)
		if err != nil {
			t.Errorf("Subtest query failed: %v", err)
		}
	}

	err = tx.Rollback()
	if err != nil {
		t.Errorf("Rollback failed: %v", err)
	}
}
