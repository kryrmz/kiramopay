package kyc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ── Verifications ────────────────────────────────────────────────────────────

func (r *Repository) CreateVerification(ctx context.Context, v *Verification) error {
	if v.ID == "" {
		v.ID = uuid.New().String()
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO kyc_verifications
		   (id, user_id, level_requested, status, full_legal_name, birth_date,
		    nationality, document_type, document_number, screening_result)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, NULLIF($7,''), $8, $9, $10)`,
		v.ID, v.UserID, v.LevelRequested, v.Status, v.FullLegalName, v.BirthDate,
		v.Nationality, v.DocumentType, v.DocumentNumber, v.ScreeningResult,
	)
	return err
}

func (r *Repository) AddDocument(ctx context.Context, verificationID string, d Document) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO kyc_documents (verification_id, doc_type, file_ref, sha256)
		 VALUES ($1::uuid, $2, $3, NULLIF($4,''))`,
		verificationID, d.DocType, d.FileRef, d.SHA256,
	)
	return err
}

func scanVerification(row pgx.Row) (*Verification, error) {
	v := &Verification{}
	var nationality, notes, decidedBy *string
	err := row.Scan(
		&v.ID, &v.UserID, &v.LevelRequested, &v.Status, &v.FullLegalName,
		&v.BirthDate, &nationality, &v.DocumentType, &v.DocumentNumber,
		&v.ScreeningResult, &notes, &decidedBy, &v.SubmittedAt, &v.DecidedAt,
	)
	if err != nil {
		return nil, err
	}
	if nationality != nil {
		v.Nationality = *nationality
	}
	if notes != nil {
		v.ReviewerNotes = *notes
	}
	if decidedBy != nil {
		v.DecidedBy = *decidedBy
	}
	return v, nil
}

const verificationCols = `id::text, user_id::text, level_requested, status, full_legal_name,
	birth_date, nationality, document_type, document_number, screening_result,
	reviewer_notes, decided_by::text, submitted_at, decided_at`

func (r *Repository) GetVerificationByID(ctx context.Context, id string) (*Verification, error) {
	return scanVerification(r.db.QueryRow(ctx,
		`SELECT `+verificationCols+` FROM kyc_verifications WHERE id = $1::uuid`, id))
}

// GetLatestVerification returns the most recent verification, or (nil, nil) if
// the user has never submitted one.
func (r *Repository) GetLatestVerification(ctx context.Context, userID string) (*Verification, error) {
	v, err := scanVerification(r.db.QueryRow(ctx,
		`SELECT `+verificationCols+` FROM kyc_verifications
		 WHERE user_id = $1::uuid ORDER BY submitted_at DESC LIMIT 1`, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

// UpdateDecision records an approve/reject decision on a verification.
func (r *Repository) UpdateDecision(ctx context.Context, id, status, decidedBy, notes string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE kyc_verifications
		 SET status = $2, decided_by = NULLIF($3,'')::uuid, reviewer_notes = NULLIF($4,''),
		     decided_at = NOW()
		 WHERE id = $1::uuid`,
		id, status, decidedBy, notes,
	)
	return err
}

func (r *Repository) UpdateScreeningResult(ctx context.Context, id, result string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE kyc_verifications SET screening_result = $2 WHERE id = $1::uuid`, id, result)
	return err
}

// ── Sanction screening ───────────────────────────────────────────────────────

// ScreenSanctions matches a normalized query name against the watchlist using
// exact + bidirectional substring containment.
func (r *Repository) ScreenSanctions(ctx context.Context, normalizedQuery string) ([]SanctionMatch, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id::text, source, full_name, COALESCE(program,'')
		 FROM sanction_list
		 WHERE normalized_name = $1
		    OR normalized_name LIKE '%'||$1||'%'
		    OR $1 LIKE '%'||normalized_name||'%'`,
		normalizedQuery,
	)
	if err != nil {
		return nil, fmt.Errorf("screen query: %w", err)
	}
	defer rows.Close()

	var out []SanctionMatch
	for rows.Next() {
		var m SanctionMatch
		if err := rows.Scan(&m.ID, &m.Source, &m.FullName, &m.Program); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *Repository) RecordScreening(ctx context.Context, userID string, verificationID *string, queryName, normalizedQuery, result string, matchedIDs []string) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO sanction_screenings
		   (user_id, verification_id, query_name, normalized_query, result, match_count, matched_ids)
		 VALUES (NULLIF($1,'')::uuid, $2::uuid, $3, $4, $5, $6, NULLIF($7,''))`,
		userID, verificationID, queryName, normalizedQuery, result,
		len(matchedIDs), strings.Join(matchedIDs, ","),
	)
	return err
}

// ── User KYC level + wallet limits ───────────────────────────────────────────

func (r *Repository) GetUserKYC(ctx context.Context, userID string) (level int, status string, err error) {
	err = r.db.QueryRow(ctx,
		`SELECT kyc_level, COALESCE(kyc_status,'pending') FROM users WHERE id = $1::uuid`, userID,
	).Scan(&level, &status)
	return level, status, err
}

// GetUserIdentity returns the plaintext cedula (decrypted at rest), the account
// first/last name (stored in plaintext), and the searchable cedula HMAC token.
// Used by the automated N1 identity check so it verifies the user's OWN
// registered cedula (no client-supplied id to spoof).
func (r *Repository) GetUserIdentity(ctx context.Context, userID string) (cedula, firstName, lastName, cedulaHash string, err error) {
	err = r.db.QueryRow(ctx,
		`SELECT fn_pii_decrypt(cedula_enc), first_name, last_name, cedula_hash
		 FROM users WHERE id = $1::uuid AND deleted_at IS NULL`, userID,
	).Scan(&cedula, &firstName, &lastName, &cedulaHash)
	return cedula, firstName, lastName, cedulaHash, err
}

// RecordIdentityVerification stores the outcome of an automated identity check
// (existence + matched name + id type only).
func (r *Repository) RecordIdentityVerification(ctx context.Context, userID, cedulaHash, verifiedName, idType, source string, matched bool) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO identity_verifications (user_id, cedula_hash, verified_name, id_type, source, matched)
		 VALUES ($1::uuid, $2, NULLIF($3,''), NULLIF($4,''), $5, $6)`,
		userID, cedulaHash, verifiedName, idType, source, matched,
	)
	return err
}

// ApplyApproval bumps the user's KYC level/status and scales their wallet
// limits to the new level — all in one transaction.
func (r *Repository) ApplyApproval(ctx context.Context, userID string, level int, status string, lim Limits) error {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx,
		`UPDATE users SET kyc_level = $2, kyc_status = $3, kyc_verified_at = NOW(), updated_at = NOW()
		 WHERE id = $1::uuid`,
		userID, level, status,
	); err != nil {
		return fmt.Errorf("update user kyc: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE wallets SET daily_limit = $2, monthly_limit = $3,
		        daily_limit_usd = $4, monthly_limit_usd = $5, updated_at = NOW()
		 WHERE user_id = $1::uuid`,
		userID, lim.DailyMinor, lim.MonthlyMinor, lim.DailyMinorUSD, lim.MonthlyMinorUSD,
	); err != nil {
		return fmt.Errorf("update wallet limits: %w", err)
	}
	return tx.Commit(ctx)
}
