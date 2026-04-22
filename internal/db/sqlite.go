package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"

	_ "modernc.org/sqlite"
)

// SQLiteDB wraps a database/sql connection for SQLite.
type SQLiteDB struct {
	DB *sql.DB
}

// NewSQLiteDB opens or creates a SQLite database at dbPath.
func NewSQLiteDB(dbPath string) (*SQLiteDB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON&_busy_timeout=5000", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	// Set pragmas
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("set pragma %q: %w", p, err)
		}
	}

	// Set file permissions (best-effort, not all OS support this after creation)
	_ = os.Chmod(dbPath, 0600)

	log.Info().Str("path", dbPath).Msg("sqlite database connection established")
	return &SQLiteDB{DB: db}, nil
}

// Close shuts down the SQLite database connection.
func (s *SQLiteDB) Close() {
	_ = s.DB.Close()
	log.Info().Msg("sqlite database connection closed")
}

// RunMigrations executes SQLite migrations from the migrations/sqlite directory.
func (s *SQLiteDB) RunMigrations(ctx context.Context, migrationsDir string) error {
	if migrationsDir == "" {
		migrationsDir = "migrations/sqlite"
	}

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read sqlite migrations directory %s: %w", migrationsDir, err)
	}

	// Ensure schema_migrations table exists
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".sql" {
			continue
		}

		// Check if already applied
		var exists int
		if err := s.DB.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE version = ?", name,
		).Scan(&exists); err == nil && exists > 0 {
			log.Debug().Str("migration", name).Msg("already applied, skipping")
			continue
		}

		content, err := os.ReadFile(filepath.Join(migrationsDir, name)) // #nosec G304 -- migrationsDir from server config
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if _, err := s.DB.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("execute migration %s: %w", name, err)
		}
		if _, err := s.DB.ExecContext(ctx,
			"INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)", name,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		log.Info().Str("migration", name).Msg("applied sqlite migration")
	}
	return nil
}
