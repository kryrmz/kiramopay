package transaction

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// Pool returns the underlying pool (used by Service to begin its own tx).
func (r *Repository) Pool() *pgxpool.Pool { return r.db }

// counterpartyNameMax is the width of transactions.counterparty_name
// (migration 001). Names now come from sources with WIDER columns —
// qr_merchants.name is VARCHAR(200), and users.first_name + last_name can
// concatenate to 201 — so an over-long name would abort the INSERT with
// SQLSTATE 22001 and, since CreateTransfer aborts on any non-duplicate error,
// fail the whole payment. A display name is never worth failing money over:
// truncate it here, at the single choke point every caller goes through.
const counterpartyNameMax = 100

// truncateCounterpartyName cuts on RUNE boundaries: Postgres counts characters,
// not bytes, and slicing bytes would split a multi-byte rune (an accented name
// is routine here) into invalid UTF-8.
func truncateCounterpartyName(name string) string {
	if len(name) <= counterpartyNameMax {
		return name // fast path: ASCII-length under the cap is always fine
	}
	runes := []rune(name)
	if len(runes) <= counterpartyNameMax {
		return name
	}
	return string(runes[:counterpartyNameMax])
}

// Create inserts a transaction in pending status with idempotency_key
// promoted to its own column (and metadata still preserved for legacy reads).
// If a row already exists for (user_id, idempotency_key), returns it with
// ErrDuplicate so the caller can short-circuit.
func (r *Repository) Create(ctx context.Context, userID, walletID string, req *CreateTransactionRequest) (*TransactionRecord, error) {
	return r.CreateTx(ctx, r.db, userID, walletID, req)
}

// CreateTx is the tx-aware version used by Service inside an open transaction.
func (r *Repository) CreateTx(
	ctx context.Context,
	q pgxQuerier,
	userID, walletID string,
	req *CreateTransactionRequest,
) (*TransactionRecord, error) {
	id := uuid.New().String()
	now := time.Now()
	createdDate := now.Format("2006-01-02")

	metadata := "{}"

	tx := &TransactionRecord{
		ID:                id,
		WalletID:          walletID,
		UserID:            userID,
		Type:              req.Type,
		Amount:            req.Amount,
		Currency:          req.Currency,
		Fee:               req.Fee,
		CounterpartyType:  req.CounterpartyType,
		CounterpartyName:  truncateCounterpartyName(req.CounterpartyName),
		CounterpartyPhone: req.CounterpartyPhone,
		Status:            StatusPending,
		Metadata:          metadata,
		CreatedAt:         now,
		CreatedDate:       createdDate,
	}

	idem := req.IdempotencyKey
	_, err := q.Exec(ctx,
		`INSERT INTO transactions
		   (id, wallet_id, user_id, type, amount, currency, fee,
		    counterparty_type, counterparty_name, counterparty_phone,
		    status, metadata, idempotency_key, created_at, created_date)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
		         jsonb_build_object('description', COALESCE($12,'')),
		         NULLIF($13,''), $14, $15)`,
		tx.ID, tx.WalletID, tx.UserID, tx.Type, tx.Amount, tx.Currency, tx.Fee,
		tx.CounterpartyType, tx.CounterpartyName, tx.CounterpartyPhone,
		tx.Status, req.Description, idem, tx.CreatedAt, tx.CreatedDate,
	)
	if err != nil {
		// Unique violation on (user_id, idempotency_key, created_date) → duplicate.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			existing, ferr := r.FindByIdempotencyKey(ctx, userID, idem)
			if ferr == nil {
				return existing, ErrDuplicate
			}
		}
		return nil, fmt.Errorf("insert transaction: %w", err)
	}
	return tx, nil
}

// ErrDuplicate signals that an idempotent retry hit an existing row.
var ErrDuplicate = errors.New("transaction with this idempotency key already exists")

func (r *Repository) FindByID(ctx context.Context, id string) (*TransactionRecord, error) {
	tx := &TransactionRecord{}
	err := r.db.QueryRow(ctx,
		`SELECT id, wallet_id, user_id, type, amount, currency, fee,
		        COALESCE(counterparty_type, ''), COALESCE(counterparty_name, ''),
		        COALESCE(counterparty_phone, ''), status,
		        COALESCE(external_reference, ''), COALESCE(metadata::text, '{}'),
		        created_at, processed_at, completed_at, created_date::text
		 FROM transactions WHERE id = $1`,
		id,
	).Scan(
		&tx.ID, &tx.WalletID, &tx.UserID, &tx.Type, &tx.Amount, &tx.Currency, &tx.Fee,
		&tx.CounterpartyType, &tx.CounterpartyName, &tx.CounterpartyPhone,
		&tx.Status, &tx.ExternalReference, &tx.Metadata,
		&tx.CreatedAt, &tx.ProcessedAt, &tx.CompletedAt, &tx.CreatedDate,
	)
	if err != nil {
		return nil, fmt.Errorf("find transaction: %w", err)
	}
	return tx, nil
}

func (r *Repository) ListByUser(ctx context.Context, userID string, req *ListTransactionsRequest) (*TransactionListResponse, error) {
	limit := req.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	// One WHERE clause shared by the count and the page query, so the two can
	// never drift apart (they used to be built twice by hand).
	where := "user_id = $1"
	args := []interface{}{userID}
	addFilter := func(cond string, val interface{}) {
		args = append(args, val)
		where += fmt.Sprintf(" AND "+cond, len(args))
	}
	if req.Type != "" {
		addFilter("type = $%d", req.Type)
	}
	if req.Status != "" {
		addFilter("status = $%d", req.Status)
	}
	if req.Currency != "" {
		addFilter("currency = $%d", req.Currency)
	}
	if !req.From.IsZero() {
		addFilter("created_at >= $%d", req.From)
	}
	if !req.To.IsZero() {
		addFilter("created_at < $%d", req.To)
	}

	var total int
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM transactions WHERE "+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count transactions: %w", err)
	}

	query := `SELECT id, wallet_id, user_id, type, amount, currency, fee,
	                 COALESCE(counterparty_type, ''), COALESCE(counterparty_name, ''),
	                 COALESCE(counterparty_phone, ''), status,
	                 COALESCE(external_reference, ''), COALESCE(metadata::text, '{}'),
	                 created_at, processed_at, completed_at, created_date::text
	          FROM transactions WHERE ` + where +
		// id breaks ties so the order is TOTAL: two rows sharing a created_at
		// (same-instant writes are routine — a transfer inserts both legs at
		// once) would otherwise come back in an arbitrary order that Postgres
		// may vary between the queries of a paginated read, silently dropping
		// one row and repeating another across page boundaries.
		fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	queryArgs := append(append([]interface{}{}, args...), limit, offset)

	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}
	defer rows.Close()

	var transactions []TransactionRecord
	for rows.Next() {
		var tx TransactionRecord
		if err := rows.Scan(
			&tx.ID, &tx.WalletID, &tx.UserID, &tx.Type, &tx.Amount, &tx.Currency, &tx.Fee,
			&tx.CounterpartyType, &tx.CounterpartyName, &tx.CounterpartyPhone,
			&tx.Status, &tx.ExternalReference, &tx.Metadata,
			&tx.CreatedAt, &tx.ProcessedAt, &tx.CompletedAt, &tx.CreatedDate,
		); err != nil {
			return nil, fmt.Errorf("scan transaction: %w", err)
		}
		transactions = append(transactions, tx)
	}

	if transactions == nil {
		transactions = []TransactionRecord{}
	}

	return &TransactionListResponse{
		Transactions: transactions,
		Total:        total,
		Limit:        limit,
		Offset:       offset,
	}, nil
}

func (r *Repository) UpdateStatusTx(ctx context.Context, q pgxQuerier, id, status string) error {
	var setClause string
	switch status {
	case StatusProcessing:
		setClause = "status = $2, processed_at = NOW()"
	case StatusCompleted:
		setClause = "status = $2, completed_at = NOW()"
	default:
		setClause = "status = $2"
	}
	_, err := q.Exec(ctx,
		fmt.Sprintf("UPDATE transactions SET %s WHERE id = $1", setClause),
		id, status,
	)
	return err
}

func (r *Repository) UpdateStatus(ctx context.Context, id, status string) error {
	return r.UpdateStatusTx(ctx, r.db, id, status)
}

// DailyOutgoingMinor sums today's completed outgoing transactions (minor units)
// for the user in the given currency. The per-wallet daily limit is enforced
// against this computed value because wallets.daily_spent is no longer
// maintained after the journal-ledger refactor (migration 020 dropped its only
// writer), which had silently disabled the cumulative daily cap.
//
// La lista de tipos es la definicion operativa de "salida". Un tipo que saque
// dinero de la billetera y NO este aqui hace que el tope diario valga mas de lo
// que dice: se gasta el tope entero por ese camino y despues otra vez por los
// demas. Le paso a escrow_fund, que estuvo fuera de la lista mientras escrow
// tampoco consultaba el tope. Al agregar un movimiento saliente hay que
// agregarlo aqui tambien.
//
// savings_deposit queda fuera a proposito: mueve el dinero a SYSTEM:SAVINGS,
// que sigue siendo del usuario y puede retirar cuando quiera. No sale de su
// control, asi que no es gasto.
//
// payout_sent y marketplace SI estan: los dos debitan la billetera del usuario
// contra una contraparte externa. Hoy ninguno de los dos opera en produccion
// —los rieles de payout no se registran y los cobros del marketplace se
// rechazan—, pero la lista describe lo que ES una salida, no lo que esta
// encendido: el dia que se enciendan tienen que contar desde el primer
// movimiento, no desde que alguien se acuerde de agregarlos aqui.
// sqlSalidaDiaria esta en una constante, y no incrustada en la llamada, para
// que una prueba pueda leer LA MISMA cadena que se ejecuta y comprobar que la
// lista de tipos no se quede corta.
const sqlSalidaDiaria = `SELECT COALESCE(SUM(amount), 0)
		 FROM transactions
		 WHERE user_id = $1
		   AND currency = $2
		   AND status = 'completed'
		   AND created_date = CURRENT_DATE
		   AND type IN ('sinpe_send','qr_payment','bill_payment','recharge','withdrawal','p2p_send','crypto_buy','escrow_fund','payout_sent','marketplace')`

func (r *Repository) DailyOutgoingMinor(ctx context.Context, userID, currency string) (int64, error) {
	var total int64
	err := r.db.QueryRow(ctx, sqlSalidaDiaria, userID, currency).Scan(&total)
	return total, err
}

func (r *Repository) FindByIdempotencyKey(ctx context.Context, userID, key string) (*TransactionRecord, error) {
	tx := &TransactionRecord{}
	err := r.db.QueryRow(ctx,
		`SELECT id, wallet_id, user_id, type, amount, currency, fee, status,
		        COALESCE(metadata::text, '{}'), created_at, created_date::text
		 FROM transactions
		 WHERE user_id = $1 AND idempotency_key = $2
		 LIMIT 1`,
		userID, key,
	).Scan(
		&tx.ID, &tx.WalletID, &tx.UserID, &tx.Type, &tx.Amount, &tx.Currency,
		&tx.Fee, &tx.Status, &tx.Metadata, &tx.CreatedAt, &tx.CreatedDate,
	)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// pgxQuerier is satisfied by *pgxpool.Pool and pgx.Tx — lets the same SQL
// run either standalone or inside a caller-managed transaction.
type pgxQuerier interface {
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}
