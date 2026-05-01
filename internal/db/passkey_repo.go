package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PasskeyCredential represents a WebAuthn passkey stored in the vault.
type PasskeyCredential struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	CredentialID      []byte    `json:"credential_id"`
	RPID              string    `json:"rp_id"`
	RPName            string    `json:"rp_name"`
	UserHandle        []byte    `json:"user_handle"`
	Username          string    `json:"username"`
	DisplayName       string    `json:"display_name"`
	PublicKeyCBOR     []byte    `json:"public_key_cbor"`
	EncryptedPrivKey  []byte    `json:"encrypted_private_key"`
	PrivateKeyNonce   []byte    `json:"private_key_nonce"`
	SignCount         int       `json:"sign_count"`
	AAGUID            []byte    `json:"aaguid"`
	Transports        []string  `json:"transports"`
	Discoverable      bool      `json:"discoverable"`
	BackedUp          bool      `json:"backed_up"`
	Algorithm         int       `json:"algorithm"`
	CreatedAt         time.Time `json:"created_at"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
}

// HardwareAuthKey represents a hardware security key registered for vault login 2FA.
type HardwareAuthKey struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	CredentialID  []byte     `json:"credential_id"`
	PublicKeyCBOR []byte     `json:"public_key_cbor"`
	SignCount     int        `json:"sign_count"`
	AAGUID        []byte     `json:"aaguid"`
	Transports    []string   `json:"transports"`
	Name          string     `json:"name"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
}

// ── PostgreSQL Passkey Repo ──────────────────────────────────────────────────

// PgPasskeyRepo implements PasskeyRepository for PostgreSQL.
type PgPasskeyRepo struct {
	pool *pgxpool.Pool
}

// NewPgPasskeyRepo creates a new PgPasskeyRepo.
func NewPgPasskeyRepo(pool *pgxpool.Pool) *PgPasskeyRepo {
	return &PgPasskeyRepo{pool: pool}
}

func (r *PgPasskeyRepo) CreatePasskey(ctx context.Context, p PasskeyCredential) (PasskeyCredential, error) {
	var out PasskeyCredential
	err := r.pool.QueryRow(ctx,
		`INSERT INTO passkey_credentials
		 (user_id, credential_id, rp_id, rp_name, user_handle, username, display_name,
		  public_key_cbor, encrypted_private_key, private_key_nonce, sign_count,
		  aaguid, transports, discoverable, backed_up, algorithm)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		 RETURNING id, user_id, credential_id, rp_id, rp_name, user_handle, username,
		           display_name, public_key_cbor, encrypted_private_key, private_key_nonce,
		           sign_count, aaguid, transports, discoverable, backed_up, algorithm,
		           created_at, last_used_at`,
		p.UserID, p.CredentialID, p.RPID, p.RPName, p.UserHandle, p.Username,
		p.DisplayName, p.PublicKeyCBOR, p.EncryptedPrivKey, p.PrivateKeyNonce,
		p.SignCount, p.AAGUID, p.Transports, p.Discoverable, p.BackedUp, p.Algorithm,
	).Scan(
		&out.ID, &out.UserID, &out.CredentialID, &out.RPID, &out.RPName, &out.UserHandle,
		&out.Username, &out.DisplayName, &out.PublicKeyCBOR, &out.EncryptedPrivKey,
		&out.PrivateKeyNonce, &out.SignCount, &out.AAGUID, &out.Transports,
		&out.Discoverable, &out.BackedUp, &out.Algorithm, &out.CreatedAt, &out.LastUsedAt,
	)
	if err != nil {
		return out, fmt.Errorf("create passkey: %w", err)
	}
	return out, nil
}

func (r *PgPasskeyRepo) GetPasskeysByRPID(ctx context.Context, userID, rpID string) ([]PasskeyCredential, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, credential_id, rp_id, rp_name, user_handle, username,
		        display_name, public_key_cbor, encrypted_private_key, private_key_nonce,
		        sign_count, aaguid, transports, discoverable, backed_up, algorithm,
		        created_at, last_used_at
		 FROM passkey_credentials WHERE user_id=$1 AND rp_id=$2
		 ORDER BY created_at DESC`, userID, rpID)
	if err != nil {
		return nil, fmt.Errorf("get passkeys by rp_id: %w", err)
	}
	defer rows.Close()
	return scanPgPasskeys(rows)
}

func (r *PgPasskeyRepo) GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (PasskeyCredential, error) {
	var p PasskeyCredential
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, credential_id, rp_id, rp_name, user_handle, username,
		        display_name, public_key_cbor, encrypted_private_key, private_key_nonce,
		        sign_count, aaguid, transports, discoverable, backed_up, algorithm,
		        created_at, last_used_at
		 FROM passkey_credentials WHERE credential_id=$1`, credentialID,
	).Scan(
		&p.ID, &p.UserID, &p.CredentialID, &p.RPID, &p.RPName, &p.UserHandle,
		&p.Username, &p.DisplayName, &p.PublicKeyCBOR, &p.EncryptedPrivKey,
		&p.PrivateKeyNonce, &p.SignCount, &p.AAGUID, &p.Transports,
		&p.Discoverable, &p.BackedUp, &p.Algorithm, &p.CreatedAt, &p.LastUsedAt,
	)
	if err == pgx.ErrNoRows {
		return p, fmt.Errorf("passkey not found")
	}
	if err != nil {
		return p, fmt.Errorf("get passkey by credential_id: %w", err)
	}
	return p, nil
}

func (r *PgPasskeyRepo) GetAllPasskeys(ctx context.Context, userID string) ([]PasskeyCredential, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, credential_id, rp_id, rp_name, user_handle, username,
		        display_name, public_key_cbor, encrypted_private_key, private_key_nonce,
		        sign_count, aaguid, transports, discoverable, backed_up, algorithm,
		        created_at, last_used_at
		 FROM passkey_credentials WHERE user_id=$1
		 ORDER BY rp_id, created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("get all passkeys: %w", err)
	}
	defer rows.Close()
	return scanPgPasskeys(rows)
}

func (r *PgPasskeyRepo) UpdateSignCount(ctx context.Context, credentialID []byte, newCount int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE passkey_credentials SET sign_count=$1, last_used_at=now() WHERE credential_id=$2`,
		newCount, credentialID)
	if err != nil {
		return fmt.Errorf("update sign count: %w", err)
	}
	return nil
}

func (r *PgPasskeyRepo) DeletePasskey(ctx context.Context, userID, passkeyID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM passkey_credentials WHERE id=$1 AND user_id=$2`, passkeyID, userID)
	if err != nil {
		return fmt.Errorf("delete passkey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("passkey not found")
	}
	return nil
}

func scanPgPasskeys(rows pgx.Rows) ([]PasskeyCredential, error) {
	var result []PasskeyCredential
	for rows.Next() {
		var p PasskeyCredential
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.CredentialID, &p.RPID, &p.RPName, &p.UserHandle,
			&p.Username, &p.DisplayName, &p.PublicKeyCBOR, &p.EncryptedPrivKey,
			&p.PrivateKeyNonce, &p.SignCount, &p.AAGUID, &p.Transports,
			&p.Discoverable, &p.BackedUp, &p.Algorithm, &p.CreatedAt, &p.LastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("scan passkey: %w", err)
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// ── PostgreSQL Hardware Key Repo ─────────────────────────────────────────────

// PgHardwareKeyRepo implements HardwareKeyRepository for PostgreSQL.
type PgHardwareKeyRepo struct {
	pool *pgxpool.Pool
}

// NewPgHardwareKeyRepo creates a new PgHardwareKeyRepo.
func NewPgHardwareKeyRepo(pool *pgxpool.Pool) *PgHardwareKeyRepo {
	return &PgHardwareKeyRepo{pool: pool}
}

func (r *PgHardwareKeyRepo) RegisterHardwareKey(ctx context.Context, k HardwareAuthKey) (HardwareAuthKey, error) {
	var out HardwareAuthKey
	err := r.pool.QueryRow(ctx,
		`INSERT INTO hardware_auth_keys
		 (user_id, credential_id, public_key_cbor, sign_count, aaguid, transports, name)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING id, user_id, credential_id, public_key_cbor, sign_count, aaguid, transports,
		           name, created_at, last_used_at`,
		k.UserID, k.CredentialID, k.PublicKeyCBOR, k.SignCount, k.AAGUID, k.Transports, k.Name,
	).Scan(
		&out.ID, &out.UserID, &out.CredentialID, &out.PublicKeyCBOR, &out.SignCount,
		&out.AAGUID, &out.Transports, &out.Name, &out.CreatedAt, &out.LastUsedAt,
	)
	if err != nil {
		return out, fmt.Errorf("register hardware key: %w", err)
	}
	return out, nil
}

func (r *PgHardwareKeyRepo) GetHardwareKeys(ctx context.Context, userID string) ([]HardwareAuthKey, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, credential_id, public_key_cbor, sign_count, aaguid, transports,
		        name, created_at, last_used_at
		 FROM hardware_auth_keys WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("get hardware keys: %w", err)
	}
	defer rows.Close()

	var result []HardwareAuthKey
	for rows.Next() {
		var k HardwareAuthKey
		if err := rows.Scan(
			&k.ID, &k.UserID, &k.CredentialID, &k.PublicKeyCBOR, &k.SignCount,
			&k.AAGUID, &k.Transports, &k.Name, &k.CreatedAt, &k.LastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("scan hardware key: %w", err)
		}
		result = append(result, k)
	}
	return result, rows.Err()
}

func (r *PgHardwareKeyRepo) GetHardwareKeyByCredentialID(ctx context.Context, credentialID []byte) (HardwareAuthKey, error) {
	var k HardwareAuthKey
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, credential_id, public_key_cbor, sign_count, aaguid, transports,
		        name, created_at, last_used_at
		 FROM hardware_auth_keys WHERE credential_id=$1`, credentialID,
	).Scan(
		&k.ID, &k.UserID, &k.CredentialID, &k.PublicKeyCBOR, &k.SignCount,
		&k.AAGUID, &k.Transports, &k.Name, &k.CreatedAt, &k.LastUsedAt,
	)
	if err == pgx.ErrNoRows {
		return k, fmt.Errorf("hardware key not found")
	}
	if err != nil {
		return k, fmt.Errorf("get hardware key by credential_id: %w", err)
	}
	return k, nil
}

func (r *PgHardwareKeyRepo) UpdateHardwareKeySignCount(ctx context.Context, credentialID []byte, count int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE hardware_auth_keys SET sign_count=$1, last_used_at=now() WHERE credential_id=$2`,
		count, credentialID)
	if err != nil {
		return fmt.Errorf("update hardware key sign count: %w", err)
	}
	return nil
}

func (r *PgHardwareKeyRepo) DeleteHardwareKey(ctx context.Context, userID, keyID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM hardware_auth_keys WHERE id=$1 AND user_id=$2`, keyID, userID)
	if err != nil {
		return fmt.Errorf("delete hardware key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("hardware key not found")
	}
	return nil
}

// ── SQLite Passkey Repo ──────────────────────────────────────────────────────

// SQLitePasskeyRepo implements PasskeyRepository for SQLite.
type SQLitePasskeyRepo struct {
	db *sql.DB
}

// NewSQLitePasskeyRepo creates a new SQLitePasskeyRepo.
func NewSQLitePasskeyRepo(db *sql.DB) *SQLitePasskeyRepo {
	return &SQLitePasskeyRepo{db: db}
}

func (r *SQLitePasskeyRepo) CreatePasskey(ctx context.Context, p PasskeyCredential) (PasskeyCredential, error) {
	id := newUUID()
	now := nowUTC()
	transports := strings.Join(p.Transports, ",")
	disc := 0
	if p.Discoverable {
		disc = 1
	}
	bu := 0
	if p.BackedUp {
		bu = 1
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO passkey_credentials
		 (id, user_id, credential_id, rp_id, rp_name, user_handle, username, display_name,
		  public_key_cbor, encrypted_private_key, private_key_nonce, sign_count,
		  aaguid, transports, discoverable, backed_up, algorithm, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, p.UserID, p.CredentialID, p.RPID, p.RPName, p.UserHandle, p.Username,
		p.DisplayName, p.PublicKeyCBOR, p.EncryptedPrivKey, p.PrivateKeyNonce,
		p.SignCount, p.AAGUID, transports, disc, bu, p.Algorithm, now,
	)
	if err != nil {
		return PasskeyCredential{}, fmt.Errorf("create passkey: %w", err)
	}

	p.ID = id
	p.CreatedAt = parseTime(now)
	return p, nil
}

func (r *SQLitePasskeyRepo) GetPasskeysByRPID(ctx context.Context, userID, rpID string) ([]PasskeyCredential, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, rp_id, rp_name, user_handle, username,
		        display_name, public_key_cbor, encrypted_private_key, private_key_nonce,
		        sign_count, aaguid, transports, discoverable, backed_up, algorithm,
		        created_at, last_used_at
		 FROM passkey_credentials WHERE user_id=? AND rp_id=?
		 ORDER BY created_at DESC`, userID, rpID)
	if err != nil {
		return nil, fmt.Errorf("get passkeys by rp_id: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSQLitePasskeys(rows)
}

func (r *SQLitePasskeyRepo) GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (PasskeyCredential, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, credential_id, rp_id, rp_name, user_handle, username,
		        display_name, public_key_cbor, encrypted_private_key, private_key_nonce,
		        sign_count, aaguid, transports, discoverable, backed_up, algorithm,
		        created_at, last_used_at
		 FROM passkey_credentials WHERE credential_id=?`, credentialID)
	return scanSQLitePasskeyRow(row)
}

func (r *SQLitePasskeyRepo) GetAllPasskeys(ctx context.Context, userID string) ([]PasskeyCredential, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, rp_id, rp_name, user_handle, username,
		        display_name, public_key_cbor, encrypted_private_key, private_key_nonce,
		        sign_count, aaguid, transports, discoverable, backed_up, algorithm,
		        created_at, last_used_at
		 FROM passkey_credentials WHERE user_id=?
		 ORDER BY rp_id, created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("get all passkeys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSQLitePasskeys(rows)
}

func (r *SQLitePasskeyRepo) UpdateSignCount(ctx context.Context, credentialID []byte, newCount int) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE passkey_credentials SET sign_count=?, last_used_at=? WHERE credential_id=?`,
		newCount, nowUTC(), credentialID)
	if err != nil {
		return fmt.Errorf("update sign count: %w", err)
	}
	return nil
}

func (r *SQLitePasskeyRepo) DeletePasskey(ctx context.Context, userID, passkeyID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM passkey_credentials WHERE id=? AND user_id=?`, passkeyID, userID)
	if err != nil {
		return fmt.Errorf("delete passkey: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("passkey not found")
	}
	return nil
}

func scanSQLitePasskeys(rows *sql.Rows) ([]PasskeyCredential, error) {
	var result []PasskeyCredential
	for rows.Next() {
		var p PasskeyCredential
		var transports, createdAt string
		var lastUsedAt sql.NullString
		var disc, bu int
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.CredentialID, &p.RPID, &p.RPName, &p.UserHandle,
			&p.Username, &p.DisplayName, &p.PublicKeyCBOR, &p.EncryptedPrivKey,
			&p.PrivateKeyNonce, &p.SignCount, &p.AAGUID, &transports,
			&disc, &bu, &p.Algorithm, &createdAt, &lastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("scan passkey: %w", err)
		}
		p.Discoverable = disc != 0
		p.BackedUp = bu != 0
		p.CreatedAt = parseTime(createdAt)
		if lastUsedAt.Valid {
			t := parseTime(lastUsedAt.String)
			p.LastUsedAt = &t
		}
		if transports != "" {
			p.Transports = strings.Split(transports, ",")
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func scanSQLitePasskeyRow(row *sql.Row) (PasskeyCredential, error) {
	var p PasskeyCredential
	var transports, createdAt string
	var lastUsedAt sql.NullString
	var disc, bu int
	err := row.Scan(
		&p.ID, &p.UserID, &p.CredentialID, &p.RPID, &p.RPName, &p.UserHandle,
		&p.Username, &p.DisplayName, &p.PublicKeyCBOR, &p.EncryptedPrivKey,
		&p.PrivateKeyNonce, &p.SignCount, &p.AAGUID, &transports,
		&disc, &bu, &p.Algorithm, &createdAt, &lastUsedAt,
	)
	if err == sql.ErrNoRows {
		return p, fmt.Errorf("passkey not found")
	}
	if err != nil {
		return p, fmt.Errorf("scan passkey: %w", err)
	}
	p.Discoverable = disc != 0
	p.BackedUp = bu != 0
	p.CreatedAt = parseTime(createdAt)
	if lastUsedAt.Valid {
		t := parseTime(lastUsedAt.String)
		p.LastUsedAt = &t
	}
	if transports != "" {
		p.Transports = strings.Split(transports, ",")
	}
	return p, nil
}

// ── SQLite Hardware Key Repo ─────────────────────────────────────────────────

// SQLiteHardwareKeyRepo implements HardwareKeyRepository for SQLite.
type SQLiteHardwareKeyRepo struct {
	db *sql.DB
}

// NewSQLiteHardwareKeyRepo creates a new SQLiteHardwareKeyRepo.
func NewSQLiteHardwareKeyRepo(db *sql.DB) *SQLiteHardwareKeyRepo {
	return &SQLiteHardwareKeyRepo{db: db}
}

func (r *SQLiteHardwareKeyRepo) RegisterHardwareKey(ctx context.Context, k HardwareAuthKey) (HardwareAuthKey, error) {
	id := newUUID()
	now := nowUTC()
	transports := strings.Join(k.Transports, ",")

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO hardware_auth_keys
		 (id, user_id, credential_id, public_key_cbor, sign_count, aaguid, transports, name, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		id, k.UserID, k.CredentialID, k.PublicKeyCBOR, k.SignCount, k.AAGUID, transports, k.Name, now,
	)
	if err != nil {
		return HardwareAuthKey{}, fmt.Errorf("register hardware key: %w", err)
	}

	k.ID = id
	k.CreatedAt = parseTime(now)
	return k, nil
}

func (r *SQLiteHardwareKeyRepo) GetHardwareKeys(ctx context.Context, userID string) ([]HardwareAuthKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key_cbor, sign_count, aaguid, transports,
		        name, created_at, last_used_at
		 FROM hardware_auth_keys WHERE user_id=? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("get hardware keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []HardwareAuthKey
	for rows.Next() {
		var k HardwareAuthKey
		var transports, createdAt string
		var lastUsedAt sql.NullString
		if err := rows.Scan(
			&k.ID, &k.UserID, &k.CredentialID, &k.PublicKeyCBOR, &k.SignCount,
			&k.AAGUID, &transports, &k.Name, &createdAt, &lastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("scan hardware key: %w", err)
		}
		k.CreatedAt = parseTime(createdAt)
		if lastUsedAt.Valid {
			t := parseTime(lastUsedAt.String)
			k.LastUsedAt = &t
		}
		if transports != "" {
			k.Transports = strings.Split(transports, ",")
		}
		result = append(result, k)
	}
	return result, rows.Err()
}

func (r *SQLiteHardwareKeyRepo) GetHardwareKeyByCredentialID(ctx context.Context, credentialID []byte) (HardwareAuthKey, error) {
	var k HardwareAuthKey
	var transports, createdAt string
	var lastUsedAt sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, credential_id, public_key_cbor, sign_count, aaguid, transports,
		        name, created_at, last_used_at
		 FROM hardware_auth_keys WHERE credential_id=?`, credentialID,
	).Scan(
		&k.ID, &k.UserID, &k.CredentialID, &k.PublicKeyCBOR, &k.SignCount,
		&k.AAGUID, &transports, &k.Name, &createdAt, &lastUsedAt,
	)
	if err == sql.ErrNoRows {
		return k, fmt.Errorf("hardware key not found")
	}
	if err != nil {
		return k, fmt.Errorf("get hardware key by credential_id: %w", err)
	}
	k.CreatedAt = parseTime(createdAt)
	if lastUsedAt.Valid {
		t := parseTime(lastUsedAt.String)
		k.LastUsedAt = &t
	}
	if transports != "" {
		k.Transports = strings.Split(transports, ",")
	}
	return k, nil
}

func (r *SQLiteHardwareKeyRepo) UpdateHardwareKeySignCount(ctx context.Context, credentialID []byte, count int) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE hardware_auth_keys SET sign_count=?, last_used_at=? WHERE credential_id=?`,
		count, nowUTC(), credentialID)
	if err != nil {
		return fmt.Errorf("update hardware key sign count: %w", err)
	}
	return nil
}

func (r *SQLiteHardwareKeyRepo) DeleteHardwareKey(ctx context.Context, userID, keyID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM hardware_auth_keys WHERE id=? AND user_id=?`, keyID, userID)
	if err != nil {
		return fmt.Errorf("delete hardware key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("hardware key not found")
	}
	return nil
}
