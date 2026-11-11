package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitFilePermissions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sub", "panel.db")
	db, err := Init(dbPath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB: %v", err)
	}
	defer sqlDB.Close()

	if st, err := os.Stat(filepath.Dir(dbPath)); err != nil || st.Mode().Perm() != 0700 {
		t.Fatalf("database dir perms = %v (err %v), want 0700", st.Mode().Perm(), err)
	}
	if st, err := os.Stat(dbPath); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("database file perms = %v (err %v), want 0600", st.Mode().Perm(), err)
	}
}

func TestInitMemory(t *testing.T) {
	db, err := Init(":memory:")
	if err != nil {
		t.Fatalf("Init(:memory:): %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB: %v", err)
	}
	defer sqlDB.Close()
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("ping :memory: db: %v", err)
	}
}
