package transaction

import (
	"strings"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/kiramopay/backend/internal/audit"
	"github.com/kiramopay/backend/internal/ledger"
	"github.com/kiramopay/backend/internal/wallet"
)

// MFAEnforcer (optional) gates high-value transactions. If non-nil and
// IsMFARequired returns true, the service expects a prior verified challenge
// for the user before the transaction proceeds.
type MFAEnforcer interface {
	IsMFARequired(amountMinor int64, currency string) bool
	HasVerifiedMFA(ctx context.Context, userID, purpose string) (bool, error)
}

// UIFReporter (optional) is notified, best-effort, after an outgoing
// transaction posts, so it can evaluate AML/UIF reporting thresholds. It must
// not block or fail the transaction.
type UIFReporter interface {
	Report(ctx context.Context, userID, txID, currency string, amountMinor int64)
}

type Service struct {
	repo        *Repository
	walletRepo  *wallet.Repository
	ledger      *ledger.Engine
	auditLogger *audit.Logger
	mfa         MFAEnforcer
	uif         UIFReporter
}

// Options carries optional collaborators.
type Options struct {
	AuditLogger *audit.Logger
	MFA         MFAEnforcer
	UIF         UIFReporter
}

func NewService(repo *Repository, walletRepo *wallet.Repository, l *ledger.Engine, opts *Options) *Service {
	if opts == nil {
		opts = &Options{}
	}
	return &Service{
		repo:        repo,
		walletRepo:  walletRepo,
		ledger:      l,
		auditLogger: opts.AuditLogger,
		mfa:         opts.MFA,
		uif:         opts.UIF,
	}
}

// CreateTransaction is the public entry point used by HTTP handlers for
// simple user-initiated transactions. Internal callers (sinpe, qr, splitpay)
// should prefer CreateTransfer which expresses BOTH legs of a transfer.
func (s *Service) CreateTransaction(ctx context.Context, userID string, req *CreateTransactionRequest) (*TransactionRecord, error) {
	// Idempotency short-circuit BEFORE locking anything.
	if req.IdempotencyKey != "" {
		existing, err := s.repo.FindByIdempotencyKey(ctx, userID, req.IdempotencyKey)
		if err == nil && existing != nil {
			return existing, nil
		}
	}

	w, err := s.walletRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("wallet not found")
	}

	if req.Currency == "" {
		req.Currency = "CRC"
	}
	if req.Amount <= 0 {
		return nil, fmt.Errorf("amount must be positive")
	}

	// Un tipo ENTRANTE acredita desde una cuenta de sistema, asi que solo puede
	// originarlo otro servicio del backend. Sin esta puerta, cualquier tipo que
	// no estuviera en isOutgoing caia por descarte en la rama de credito y
	// acreditaba dinero real saltandose saldo, limite diario y MFA, que viven
	// todos dentro del `if` de abajo.
	if !isOutgoing(req.Type) && !req.Internal {
		return nil, ErrCreditNotAllowed
	}

	if isOutgoing(req.Type) {
		totalCost := req.Amount + req.Fee
		if req.Currency == "CRC" && w.BalanceCRC < totalCost {
			return nil, fmt.Errorf("insufficient balance")
		}
		if req.Currency == "USD" && w.BalanceUSD < totalCost {
			return nil, fmt.Errorf("insufficient balance")
		}
		if err := s.checkDailyLimit(ctx, userID, req.Currency, req.Amount, w); err != nil {
			return nil, err
		}

		if s.mfa != nil && s.mfa.IsMFARequired(req.Amount, req.Currency) {
			ok, err := s.mfa.HasVerifiedMFA(ctx, userID, "high_value_tx")
			if err != nil {
				return nil, fmt.Errorf("mfa check: %w", err)
			}
			if !ok {
				return nil, ErrMFARequired
			}
		}
	}

	// Insert tx in pending with idempotency_key persisted.
	tx, err := s.repo.Create(ctx, userID, w.ID, req)
	if err != nil {
		if errors.Is(err, ErrDuplicate) {
			return tx, nil
		}
		return nil, fmt.Errorf("create transaction: %w", err)
	}

	// Build the ledger posting for outgoing/incoming legs against the
	// SYSTEM:EXTERNAL counterparty for now (callers that know the peer should
	// use CreateTransfer instead).
	posting := s.buildSingleSidedPosting(tx, req)
	postingID, err := s.ledger.Post(ctx, posting)
	if err != nil && !errors.Is(err, ledger.ErrIdempotent) {
		_ = s.repo.UpdateStatus(ctx, tx.ID, StatusFailed)
		return nil, fmt.Errorf("post ledger: %w", err)
	}
	_ = postingID

	if err := s.repo.UpdateStatus(ctx, tx.ID, StatusCompleted); err != nil {
		return nil, fmt.Errorf("mark completed: %w", err)
	}

	if isOutgoing(req.Type) {
		if s.auditLogger != nil {
			s.auditLogger.LogTransfer(userID, tx.ID, req.Amount, req.Currency, "")
		}
		if s.uif != nil {
			s.uif.Report(ctx, userID, tx.ID, req.Currency, req.Amount)
		}
	}
	return tx, nil
}

// CreateTransferRequest carries both legs of an internal transfer.
// MerchantBalance is the shop's own balance in minor units, derived from the
// journal (no cache, so it cannot drift).
func (s *Service) MerchantBalance(ctx context.Context, merchantID, currency string) (int64, error) {
	return s.ledger.MerchantBalance(ctx, merchantID, currency)
}

// WithdrawMerchantToUser moves money from a shop's balance into the owner's
// personal wallet: debit the merchant account, credit the user wallet. The
// engine updates the user's balance cache from the credit leg.
//
// The caller supplies idempotencyKey so a retried or double-tapped withdrawal
// settles once. The replay lookup runs BEFORE any balance read: a retry of a
// withdrawal that already drained the balance must return the original result,
// not "insufficient". The balance pre-check here is a fast-fail courtesy only —
// the race-free enforcement is the ledger's in-tx negativity check.
//
// merchantName is the shop's display name for the history row; this service has
// no merchant repository, and the caller already loaded the merchant to check
// ownership. Empty is fine (the frontend falls back to a generic title) — it
// used to store the merchant UUID, which surfaced raw in the history.
func (s *Service) WithdrawMerchantToUser(
	ctx context.Context, merchantID, merchantName, userID, currency string, amount int64, idempotencyKey string,
) (*TransactionRecord, error) {
	if amount <= 0 {
		return nil, fmt.Errorf("amount must be positive")
	}
	w, err := s.walletRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("wallet not found")
	}
	if idempotencyKey == "" {
		idempotencyKey = "mwithdraw:" + uuid.New().String()
	}
	if existing, _ := s.repo.FindByIdempotencyKey(ctx, userID, idempotencyKey); existing != nil {
		return existing, nil
	}
	bal, err := s.ledger.MerchantBalance(ctx, merchantID, currency)
	if err != nil {
		return nil, fmt.Errorf("read merchant balance: %w", err)
	}
	if bal < amount {
		return nil, ErrInsufficientMerchantBalance
	}

	rec, err := s.repo.Create(ctx, userID, w.ID, &CreateTransactionRequest{
		Type:             TypeMerchantWithdrawal,
		Amount:           amount,
		Currency:         currency,
		CounterpartyType: "merchant",
		CounterpartyName: merchantName,
		Description:      "Retiro del saldo del negocio",
		IdempotencyKey:   idempotencyKey,
	})
	if err != nil {
		if errors.Is(err, ErrDuplicate) {
			// A concurrent retry won the insert; it owns the posting.
			return rec, nil
		}
		return nil, fmt.Errorf("create withdrawal tx: %w", err)
	}

	_, err = s.ledger.Post(ctx, &ledger.Posting{
		Description:    fmt.Sprintf("merchant withdrawal %d %s", amount, currency),
		IdempotencyKey: idempotencyKey,
		TxID:           rec.ID,
		CreatedBy:      userID,
		Entries: []ledger.Entry{
			{Account: ledger.Account{MerchantID: merchantID}, Side: ledger.Debit, AmountMinor: amount, Currency: currency},
			{Account: ledger.Account{UserID: userID}, Side: ledger.Credit, AmountMinor: amount, Currency: currency},
		},
		Metadata: map[string]any{"merchant_id": merchantID, "to_user": userID},
	})
	if err != nil && !errors.Is(err, ledger.ErrIdempotent) {
		_ = s.repo.UpdateStatus(ctx, rec.ID, StatusFailed)
		if errors.Is(err, ledger.ErrInsufficientFunds) {
			return nil, ErrInsufficientMerchantBalance
		}
		return nil, fmt.Errorf("post withdrawal: %w", err)
	}
	if err := s.repo.UpdateStatus(ctx, rec.ID, StatusCompleted); err != nil {
		return nil, fmt.Errorf("mark completed: %w", err)
	}
	return rec, nil
}

type CreateTransferRequest struct {
	FromUserID string
	ToUserID   string
	// ToMerchantID credits a shop's own ledger balance instead of a user wallet
	// (business income is kept apart from the owner's personal money; they
	// withdraw explicitly). Mutually exclusive with ToUserID. When set there is
	// no receiver `transactions` row: the shop's record is the qr_payments row
	// plus the journal entry.
	ToMerchantID   string
	Amount         int64
	Currency       string
	Fee            int64
	Description    string
	IdempotencyKey string
	TxType         string // for the sender's transactions row
	ReceiveType    string // for the receiver's transactions row (e.g. p2p_receive)

	// SenderCounterpartyName is the display name of WHO RECEIVES, shown on the
	// sender's history row; ReceiverCounterpartyName is who sent, shown on the
	// receiver's row. Both optional — the frontend falls back to a generic
	// per-type title when empty, so callers pass what they know (SINPE knows the
	// contact, QR knows the shop) and never fail a transfer over a name.
	SenderCounterpartyName   string
	ReceiverCounterpartyName string

	// FeeFromReceiver selects who absorbs Fee. Default (false) is the historical
	// payer-absorbed model: the payer pays Amount + Fee, the receiver is credited
	// the full Amount, and Fee is booked to SYSTEM:FEES. When true (merchant
	// model), the payer pays exactly Amount, the receiver is credited
	// Amount - Fee, and Fee is booked to SYSTEM:FEES. Either way the posting is
	// balanced and Fee always lands in SYSTEM:FEES.
	FeeFromReceiver bool
}

// CreateTransfer atomically debits sender, credits receiver, books fee to
// SYSTEM:FEES, and writes 2 transactions rows (one each). All in one tx.
func (s *Service) CreateTransfer(ctx context.Context, req *CreateTransferRequest) (sender, receiver *TransactionRecord, err error) {
	if req.Amount <= 0 {
		return nil, nil, fmt.Errorf("amount must be positive")
	}
	toMerchant := req.ToMerchantID != ""
	if toMerchant && req.ToUserID != "" {
		return nil, nil, fmt.Errorf("only one of ToUserID/ToMerchantID allowed")
	}
	if !toMerchant && req.ToUserID == "" {
		return nil, nil, fmt.Errorf("receiver required")
	}
	if !toMerchant && req.FromUserID == req.ToUserID {
		return nil, nil, fmt.Errorf("sender and receiver must differ")
	}
	if req.Fee < 0 {
		return nil, nil, fmt.Errorf("fee must not be negative")
	}
	// In the merchant model the fee is carved out of the amount, so it must leave
	// a positive credit for the receiver (the ledger rejects non-positive entries).
	if req.FeeFromReceiver && req.Fee >= req.Amount {
		return nil, nil, fmt.Errorf("fee must be less than amount")
	}
	if req.Currency == "" {
		req.Currency = "CRC"
	}

	// Idempotency: if already done, return BOTH existing rows. The receiver leg
	// was stored under the derived "recv" key, so look it up too — callers that
	// record a follow-on row keyed off the receiver can then detect the replay.
	if req.IdempotencyKey != "" {
		if existing, _ := s.repo.FindByIdempotencyKey(ctx, req.FromUserID, req.IdempotencyKey); existing != nil {
			// A merchant collection has no receiver row to replay.
			var recv *TransactionRecord
			if !toMerchant {
				recv, _ = s.repo.FindByIdempotencyKey(ctx, req.ToUserID, pairKey(req.IdempotencyKey, "recv"))
			}
			return existing, recv, nil
		}
	}

	senderWallet, err := s.walletRepo.FindByUserID(ctx, req.FromUserID)
	if err != nil {
		return nil, nil, fmt.Errorf("sender wallet not found")
	}
	var receiverWallet *wallet.WalletRecord
	if !toMerchant {
		receiverWallet, err = s.walletRepo.FindByUserID(ctx, req.ToUserID)
		if err != nil {
			return nil, nil, fmt.Errorf("receiver wallet not found")
		}
	}

	// The payer only funds the fee when it is payer-absorbed; in the merchant
	// model the fee comes out of the receiver's credit, so the payer needs Amount.
	senderTotal := req.Amount
	if !req.FeeFromReceiver {
		senderTotal += req.Fee
	}
	if req.Currency == "CRC" && senderWallet.BalanceCRC < senderTotal {
		return nil, nil, fmt.Errorf("insufficient balance")
	}
	if req.Currency == "USD" && senderWallet.BalanceUSD < senderTotal {
		return nil, nil, fmt.Errorf("insufficient balance")
	}
	if err := s.checkDailyLimit(ctx, req.FromUserID, req.Currency, req.Amount, senderWallet); err != nil {
		return nil, nil, err
	}

	if s.mfa != nil && s.mfa.IsMFARequired(req.Amount, req.Currency) {
		ok, err := s.mfa.HasVerifiedMFA(ctx, req.FromUserID, "high_value_tx")
		if err != nil {
			return nil, nil, fmt.Errorf("mfa check: %w", err)
		}
		if !ok {
			return nil, nil, ErrMFARequired
		}
	}

	// The fee shows on whichever party absorbs it: the payer's row in the classic
	// model, the receiver's row (a deduction from what they collect) in the
	// merchant model.
	senderFee, receiverFee := req.Fee, int64(0)
	if req.FeeFromReceiver {
		senderFee, receiverFee = 0, req.Fee
	}
	senderReq := &CreateTransactionRequest{
		Type:             req.TxType,
		Amount:           req.Amount,
		Currency:         req.Currency,
		Fee:              senderFee,
		CounterpartyType: "user",
		CounterpartyName: req.SenderCounterpartyName,
		Description:      req.Description,
		IdempotencyKey:   req.IdempotencyKey,
	}
	receiveReq := &CreateTransactionRequest{
		Type:             req.ReceiveType,
		Amount:           req.Amount,
		Currency:         req.Currency,
		Fee:              receiverFee,
		CounterpartyType: "user",
		CounterpartyName: req.ReceiverCounterpartyName,
		Description:      req.Description,
		// Receiver idempotency: derive deterministically to avoid double-credit.
		IdempotencyKey: pairKey(req.IdempotencyKey, "recv"),
	}

	sender, err = s.repo.Create(ctx, req.FromUserID, senderWallet.ID, senderReq)
	if err != nil && !errors.Is(err, ErrDuplicate) {
		return nil, nil, fmt.Errorf("create sender tx: %w", err)
	}
	// A shop is not a user: its side of the collection is the qr_payments row
	// plus the journal entry, so there is no receiver `transactions` row.
	if !toMerchant {
		receiver, err = s.repo.Create(ctx, req.ToUserID, receiverWallet.ID, receiveReq)
		if err != nil && !errors.Is(err, ErrDuplicate) {
			return nil, nil, fmt.Errorf("create receiver tx: %w", err)
		}
	}

	// Build the balanced posting. Two fee models, both booking Fee to SYSTEM:FEES:
	//   payer-absorbed (default): payer -Amount-Fee, receiver +Amount, fees +Fee.
	//   merchant-absorbed (FeeFromReceiver): payer -Amount, receiver +Amount-Fee, fees +Fee.
	feeAccount := ledger.SystemFeesCRC
	if req.Currency == "USD" {
		feeAccount = ledger.SystemFeesUSD
	}
	// The credit leg lands either in a user wallet or in the shop's own account.
	creditAccount := ledger.Account{UserID: req.ToUserID}
	if toMerchant {
		creditAccount = ledger.Account{MerchantID: req.ToMerchantID}
	}
	var entries []ledger.Entry
	if req.Fee > 0 && req.FeeFromReceiver {
		entries = []ledger.Entry{
			{Account: ledger.Account{UserID: req.FromUserID}, Side: ledger.Debit, AmountMinor: req.Amount, Currency: req.Currency},
			{Account: creditAccount, Side: ledger.Credit, AmountMinor: req.Amount - req.Fee, Currency: req.Currency},
			{Account: ledger.Account{SystemCode: feeAccount}, Side: ledger.Credit, AmountMinor: req.Fee, Currency: req.Currency},
		}
	} else {
		entries = []ledger.Entry{
			{Account: ledger.Account{UserID: req.FromUserID}, Side: ledger.Debit, AmountMinor: req.Amount, Currency: req.Currency},
			{Account: creditAccount, Side: ledger.Credit, AmountMinor: req.Amount, Currency: req.Currency},
		}
		if req.Fee > 0 {
			entries = append(entries,
				ledger.Entry{Account: ledger.Account{UserID: req.FromUserID}, Side: ledger.Debit, AmountMinor: req.Fee, Currency: req.Currency},
				ledger.Entry{Account: ledger.Account{SystemCode: feeAccount}, Side: ledger.Credit, AmountMinor: req.Fee, Currency: req.Currency},
			)
		}
	}

	p := &ledger.Posting{
		Description:    fmt.Sprintf("transfer %s %d %s", req.TxType, req.Amount, req.Currency),
		IdempotencyKey: req.IdempotencyKey,
		TxID:           sender.ID,
		CreatedBy:      req.FromUserID,
		Entries:        entries,
		Metadata: map[string]any{
			"from_user":   req.FromUserID,
			"to_user":     req.ToUserID,
			"to_merchant": req.ToMerchantID,
			"description": req.Description,
		},
	}
	// A merchant collection has no receiver row (`receiver` is nil): the shop's
	// record is qr_payments + the journal entry.
	if _, err := s.ledger.Post(ctx, p); err != nil && !errors.Is(err, ledger.ErrIdempotent) {
		_ = s.repo.UpdateStatus(ctx, sender.ID, StatusFailed)
		if receiver != nil {
			_ = s.repo.UpdateStatus(ctx, receiver.ID, StatusFailed)
		}
		return nil, nil, fmt.Errorf("post ledger: %w", err)
	}

	_ = s.repo.UpdateStatus(ctx, sender.ID, StatusCompleted)
	if receiver != nil {
		_ = s.repo.UpdateStatus(ctx, receiver.ID, StatusCompleted)
	}

	if s.auditLogger != nil {
		s.auditLogger.LogTransfer(req.FromUserID, sender.ID, req.Amount, req.Currency, "")
	}
	if s.uif != nil {
		s.uif.Report(ctx, req.FromUserID, sender.ID, req.Currency, req.Amount)
	}
	return sender, receiver, nil
}

// ErrCreditNotAllowed indica que se pidio un tipo entrante desde fuera del
// backend. Acreditar dinero lo decide el servicio que sabe de donde viene.
var ErrCreditNotAllowed = errors.New("this transaction type cannot be requested by a client")

// ErrMFARequired indicates the user must verify MFA before this tx proceeds.
var ErrMFARequired = errors.New("mfa challenge required")

// ErrDailyLimitExceeded: la salida del dia superaria el tope de la billetera,
// que depende del nivel de KYC (kyc.LevelLimits). El texto es exactamente el
// que ya salia al cliente antes de existir el sentinela, para no cambiarle el
// mensaje a nadie.
var ErrDailyLimitExceeded = errors.New("daily spending limit exceeded")

// ErrMonedaSinTope: se intento sacar dinero en una moneda para la que no hay
// tope diario definido. Dejarla pasar "sin tope" seria el mismo agujero que el
// tope por moneda vino a cerrar, con otro nombre.
var ErrMonedaSinTope = errors.New("no daily limit defined for this currency")

// ErrInsufficientMerchantBalance rejects a withdrawal larger than the shop's
// journal-derived balance. The exact string reaches the client as the 400
// message, so keep it stable.
var ErrInsufficientMerchantBalance = errors.New("insufficient business balance")

// RecordHistory inserts a COMPLETED history row for a movement whose money
// already moved through the ledger elsewhere (e.g. escrow fund/release/refund
// post directly against SYSTEM:ESCROW). It performs no balance checks and no
// posting — it only makes the movement visible in the user's transaction
// list. Idempotent via the request's IdempotencyKey (duplicates are ignored).
func (s *Service) RecordHistory(ctx context.Context, userID string, req *CreateTransactionRequest) error {
	w, err := s.walletRepo.FindByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("find wallet: %w", err)
	}
	tx, err := s.repo.Create(ctx, userID, w.ID, req)
	if err != nil {
		if errors.Is(err, ErrDuplicate) {
			return nil
		}
		return fmt.Errorf("record history: %w", err)
	}
	return s.repo.UpdateStatus(ctx, tx.ID, StatusCompleted)
}

func (s *Service) GetTransaction(ctx context.Context, id string) (*TransactionRecord, error) {
	return s.repo.FindByID(ctx, id)
}

func (s *Service) ListTransactions(ctx context.Context, userID string, req *ListTransactionsRequest) (*TransactionListResponse, error) {
	return s.repo.ListByUser(ctx, userID, req)
}

// CheckDailyLimit comprueba que sacar amountMinor hoy no pase el tope diario de
// la billetera. La expone escrow, que mueve dinero fuera de la billetera por su
// propio camino y hasta ahora no consultaba ningun tope: se podia vaciar la
// cuenta creando escrows en tramos por debajo del umbral que pide segundo
// factor. La regla vive AQUI y en ningun otro lado; duplicarla es como se
// llega a dos topes distintos.
func (s *Service) CheckDailyLimit(ctx context.Context, userID, currency string, amountMinor int64) error {
	w, err := s.walletRepo.FindByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("wallet not found")
	}
	return s.checkDailyLimit(ctx, userID, currency, amountMinor, w)
}

// topeDiarioDe elige el tope de la MONEDA del movimiento.
//
// Antes se pasaba siempre w.DailyLimit, que esta en centimos de COLON, y se
// comparaba contra el monto viniera en la moneda que viniera. En dolares eso no
// frenaba nada: USD 5.000 son 500.000 centimos, muy por debajo de los
// 10.000.000 de un tope basico, asi que una billetera en dolares podia mover
// unas 26 veces su tope — por transferencia y por escrow por igual.
//
// Devuelve false para una moneda sin tope definido. No hay conversion a
// proposito: el tipo de cambio de la base esta congelado desde su semilla y
// derivar un tope de el seria heredar ese problema.
func topeDiarioDe(w *wallet.WalletRecord, currency string) (int64, bool) {
	switch strings.ToUpper(currency) {
	case "CRC":
		return w.DailyLimit, true
	case "USD":
		return w.DailyLimitUSD, true
	}
	return 0, false
}

// checkDailyLimit es la version interna, para los llamantes que ya cargaron la
// billetera y no tienen por que volver a consultarla.
func (s *Service) checkDailyLimit(ctx context.Context, userID, currency string, amountMinor int64, w *wallet.WalletRecord) error {
	dailyLimit, conocida := topeDiarioDe(w, currency)
	if !conocida {
		// Una moneda para la que no hay tope definido no puede salir "sin
		// tope": seria exactamente el agujero que esto cierra, con otro nombre.
		return fmt.Errorf("%w: %s", ErrMonedaSinTope, currency)
	}
	if dailyLimit <= 0 {
		return nil // sin tope configurado
	}
	spentToday, err := s.repo.DailyOutgoingMinor(ctx, userID, currency)
	if err != nil {
		return fmt.Errorf("daily spend check: %w", err)
	}
	if spentToday+amountMinor > dailyLimit {
		return ErrDailyLimitExceeded
	}
	return nil
}

// buildSingleSidedPosting books external-counterparty transfers (deposits,
// withdrawals, bill payments) where the second leg is a system account.
func (s *Service) buildSingleSidedPosting(tx *TransactionRecord, req *CreateTransactionRequest) *ledger.Posting {
	// La cuenta externa y la de comisiones se eligen por la moneda del
	// movimiento. Anotar un asiento en dolares contra SYSTEM:EXTERNAL:CRC
	// —una cuenta declarada en colones— deja la contraparte externa con dos
	// monedas mezcladas y arruina cualquier conciliacion por moneda.
	external := ledger.SystemExternalCRC
	feeAccount := ledger.SystemFeesCRC
	if req.Currency == "USD" {
		external = ledger.SystemExternalUSD
		feeAccount = ledger.SystemFeesUSD
	}

	entries := []ledger.Entry{}
	if isOutgoing(req.Type) {
		entries = append(entries,
			ledger.Entry{Account: ledger.Account{UserID: tx.UserID}, Side: ledger.Debit, AmountMinor: req.Amount, Currency: req.Currency},
			ledger.Entry{Account: ledger.Account{SystemCode: external}, Side: ledger.Credit, AmountMinor: req.Amount, Currency: req.Currency},
		)
		if req.Fee > 0 {
			entries = append(entries,
				ledger.Entry{Account: ledger.Account{UserID: tx.UserID}, Side: ledger.Debit, AmountMinor: req.Fee, Currency: req.Currency},
				ledger.Entry{Account: ledger.Account{SystemCode: feeAccount}, Side: ledger.Credit, AmountMinor: req.Fee, Currency: req.Currency},
			)
		}
	} else {
		entries = append(entries,
			ledger.Entry{Account: ledger.Account{SystemCode: external}, Side: ledger.Debit, AmountMinor: req.Amount, Currency: req.Currency},
			ledger.Entry{Account: ledger.Account{UserID: tx.UserID}, Side: ledger.Credit, AmountMinor: req.Amount, Currency: req.Currency},
		)
	}

	return &ledger.Posting{
		Description:    req.Type,
		IdempotencyKey: req.IdempotencyKey,
		TxID:           tx.ID,
		CreatedBy:      tx.UserID,
		Entries:        entries,
	}
}

func pairKey(base, suffix string) string {
	if base == "" {
		return ""
	}
	return base + ":" + suffix
}

func isOutgoing(txType string) bool {
	switch txType {
	case TypeSinpeSend, TypeQRPayment, TypeBillPayment, TypeRecharge, TypeWithdrawal, TypeP2PSend, TypeCryptoBuy:
		return true
	default:
		return false
	}
}
