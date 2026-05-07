package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
// If the filesystem directory is not available (e.g. when running as an Electron
// sidecar), it falls back to migrations embedded in the binary.
func (s *SQLiteDB) RunMigrations(ctx context.Context, migrationsDir string) error {
	if migrationsDir == "" {
		migrationsDir = "migrations/sqlite"
	}

	type migrationFile struct {
		name    string
		content func() ([]byte, error)
	}

	var migrations []migrationFile

	// Try filesystem first, fall back to embedded migrations
	entries, fsErr := os.ReadDir(migrationsDir)
	if fsErr == nil {
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
				continue
			}
			name := entry.Name()
			dir := migrationsDir
			migrations = append(migrations, migrationFile{
				name: name,
				content: func() ([]byte, error) {
					return os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- migrationsDir from server config
				},
			})
		}
	} else {
		// Filesystem migrations not available — use embedded
		log.Info().Str("dir", migrationsDir).Msg("filesystem migrations not found, using embedded migrations")
		embeddedEntries, err := fs.ReadDir(EmbeddedSQLiteMigrations, "sqlite_migrations")
		if err != nil {
			return fmt.Errorf("read embedded sqlite migrations: %w", err)
		}
		for _, entry := range embeddedEntries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
				continue
			}
			name := entry.Name()
			migrations = append(migrations, migrationFile{
				name: name,
				content: func() ([]byte, error) {
					return fs.ReadFile(EmbeddedSQLiteMigrations, "sqlite_migrations/"+name)
				},
			})
		}
	}

	// Sort by filename to ensure ordering
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].name < migrations[j].name
	})

	// Ensure schema_migrations table exists
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, mf := range migrations {
		// Check if already applied
		var exists int
		if err := s.DB.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE version = ?", mf.name,
		).Scan(&exists); err == nil && exists > 0 {
			log.Debug().Str("migration", mf.name).Msg("already applied, skipping")
			continue
		}

		content, err := mf.content()
		if err != nil {
			return fmt.Errorf("read migration %s: %w", mf.name, err)
		}

		// Split multi-statement SQL and execute each statement individually.
		// modernc.org/sqlite's ExecContext only executes the first statement
		// in a multi-statement string, so we must split them.
		stmts := splitSQLStatements(string(content))
		for _, stmt := range stmts {
			if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("execute migration %s: %w", mf.name, err)
			}
		}
		if _, err := s.DB.ExecContext(ctx,
			"INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)", mf.name,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", mf.name, err)
		}
		log.Info().Str("migration", mf.name).Msg("applied sqlite migration")
	}
	return nil
}

// splitSQLStatements splits a SQL string into individual statements,
// handling BEGIN...END blocks (e.g. triggers) that contain semicolons.
func splitSQLStatements(sql string) []string {
	var stmts []string
	var current strings.Builder
	inBlock := false

	for _, line := range strings.Split(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}

		upperTrimmed := strings.ToUpper(trimmed)

		// Detect BEGIN (start of trigger/block body)
		if upperTrimmed == "BEGIN" {
			inBlock = true
			current.WriteString(line)
			current.WriteString("\n")
			continue
		}

		// Detect END; (end of trigger/block body)
		if inBlock && (upperTrimmed == "END;" || upperTrimmed == "END") {
			current.WriteString(line)
			stmt := strings.TrimSpace(current.String())
			// Remove trailing semicolon so we can add it back uniformly
			stmt = strings.TrimSuffix(stmt, ";")
			if stmt != "" {
				stmts = append(stmts, stmt)
			}
			current.Reset()
			inBlock = false
			continue
		}

		if inBlock {
			// Inside a block — don't split on semicolons
			current.WriteString(line)
			current.WriteString("\n")
		} else {
			// Outside a block — split on semicolons within the line
			parts := strings.Split(line, ";")
			for i, part := range parts {
				current.WriteString(part)
				if i < len(parts)-1 {
					// Semicolon found — flush statement
					stmt := strings.TrimSpace(current.String())
					if stmt != "" {
						stmts = append(stmts, stmt)
					}
					current.Reset()
				}
			}
			current.WriteString("\n")
		}
	}

	// Flush any remaining content
	stmt := strings.TrimSpace(current.String())
	if stmt != "" {
		stmt = strings.TrimSuffix(stmt, ";")
		if stmt != "" {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}
