package db

import "embed"

// EmbeddedSQLiteMigrations contains the SQLite migration files embedded at compile time.
// This ensures migrations are always available even when the binary runs from
// a directory that doesn't contain the migrations folder (e.g. Electron sidecar).
//
//go:embed sqlite_migrations/*.sql
var EmbeddedSQLiteMigrations embed.FS
