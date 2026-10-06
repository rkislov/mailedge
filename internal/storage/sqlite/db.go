package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps sqlite connection and repos.
type DB struct {
	sql *sql.DB
	path string
}

// Open opens/creates SQLite DB and applies migrations.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	db := &DB{sql: sqlDB, path: path}
	if err := db.Migrate(context.Background()); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) SQL() *sql.DB { return db.sql }
func (db *DB) Path() string  { return db.path }

func (db *DB) Close() error { return db.sql.Close() }

// Migrate applies embedded SQL migrations in order.
func (db *DB) Migrate(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return err
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var exists string
		err := db.sql.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version=?`, e.Name()).Scan(&exists)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		tx, err := db.sql.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: %w", e.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(?,?)`,
			e.Name(), time.Now().UTC().Format(time.RFC3339)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
