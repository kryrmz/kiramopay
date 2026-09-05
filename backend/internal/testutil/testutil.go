// Package testutil provides helpers for integration tests.
// Tests require a running PostgreSQL and Redis. Set TEST_DB_DSN and TEST_REDIS_ADDR
// environment variables, or use the defaults (localhost with docker-compose).
package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// testPIIKey is the fixed PII encryption key for tests, set as the
// kiramopay.encryption_key GUC on every connection so pgcrypto fn_pii_* work.
const testPIIKey = "test-pii-encryption-key-0123456789ab"

// TestDB returns a pgxpool connected to the test database.
// It creates all tables and truncates them after the test.
func TestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = "postgres://kiramopay:kiramopay_dev@localhost:5432/kiramopay_test?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Skipf("Skipping integration test: cannot parse test DB DSN: %v", err)
	}
	// Set the PII encryption GUC per connection so pgcrypto fn_pii_* can
	// encrypt/decrypt user PII (mirrors the app's NewPostgresPool AfterConnect).
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SELECT set_config('kiramopay.encryption_key', $1, false)`, testPIIKey)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Skipf("Skipping integration test: cannot connect to test DB: %v", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("Skipping integration test: cannot ping test DB: %v", err)
	}

	if err := createSchema(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("Failed to create schema: %v", err)
	}

	if err := truncateAll(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("Failed to reset test DB: %v", err)
	}

	t.Cleanup(func() {
		if err := truncateAll(context.Background(), pool); err != nil {
			t.Errorf("cleanup: failed to reset test DB: %v", err)
		}
		pool.Close()
	})

	return pool
}

// TestRedis returns a Redis client connected to the test instance.
func TestRedis(t *testing.T) *redis.Client {
	t.Helper()

	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	client := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   15,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		t.Skipf("Skipping integration test: cannot connect to Redis: %v", err)
	}

	client.FlushDB(ctx)

	t.Cleanup(func() {
		client.FlushDB(context.Background())
		client.Close()
	})

	return client
}

func createSchema(ctx context.Context, pool *pgxpool.Pool) error {
	schema := `
	CREATE EXTENSION IF NOT EXISTS "pgcrypto";

	-- PII-at-rest helpers (mirror migration 024). The encryption key is read from
	-- the kiramopay.encryption_key GUC, set per connection in TestDB.
	CREATE OR REPLACE FUNCTION fn_encryption_key() RETURNS TEXT AS $FN$
	DECLARE k TEXT;
	BEGIN
		BEGIN k := current_setting('kiramopay.encryption_key'); EXCEPTION WHEN OTHERS THEN k := NULL; END;
		IF k IS NULL OR length(k) < 32 THEN RAISE EXCEPTION 'kiramopay.encryption_key not set'; END IF;
		RETURN k;
	END; $FN$ LANGUAGE plpgsql STABLE;

	CREATE OR REPLACE FUNCTION fn_pii_hmac(p_value TEXT) RETURNS VARCHAR(64) AS $FN$
		SELECT encode(hmac(lower(trim(p_value)), fn_encryption_key() || ':pii', 'sha256'), 'hex');
	$FN$ LANGUAGE sql STABLE;

	CREATE OR REPLACE FUNCTION fn_pii_encrypt(p_value TEXT) RETURNS BYTEA AS $FN$
		SELECT CASE WHEN p_value IS NULL OR p_value = '' THEN NULL
		            ELSE pgp_sym_encrypt(p_value, fn_encryption_key(), 'compress-algo=2, cipher-algo=aes256') END;
	$FN$ LANGUAGE sql STABLE;

	CREATE OR REPLACE FUNCTION fn_pii_decrypt(p_blob BYTEA) RETURNS TEXT AS $FN$
		SELECT CASE WHEN p_blob IS NULL THEN NULL ELSE pgp_sym_decrypt(p_blob, fn_encryption_key()) END;
	$FN$ LANGUAGE sql STABLE;

	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY,
		cedula_enc BYTEA NOT NULL,
		cedula_hash VARCHAR(64) UNIQUE NOT NULL,
		phone_enc BYTEA NOT NULL,
		phone_hash VARCHAR(64) UNIQUE NOT NULL,
		phone_verified BOOLEAN DEFAULT false,
		email_enc BYTEA,
		email_hash VARCHAR(64),
		email_verified BOOLEAN DEFAULT false,
		first_name VARCHAR(100) NOT NULL,
		last_name VARCHAR(100) NOT NULL,
		birth_date DATE,
		birth_date_enc BYTEA,
		profile_picture_url TEXT,
		password_hash TEXT NOT NULL,
		biometric_enabled BOOLEAN DEFAULT false,
		kyc_level INT DEFAULT 0,
		kyc_status VARCHAR(20) DEFAULT 'pending',
		kyc_verified_at TIMESTAMPTZ,
		role VARCHAR(20) NOT NULL DEFAULT 'user',
		-- Plan de facturacion (migracion 048). Faltaba aqui: user.GetPlan lo
		-- consulta y contra este esquema habria fallado. Este archivo declara la
		-- tabla A MANO y no lee migrations/, asi que cada columna nueva hay que
		-- ponerla en los dos lugares.
		plan VARCHAR(10) NOT NULL DEFAULT 'free',
		-- Nombre de usuario y entrada sin contrasena (migracion 058).
		username VARCHAR(20),
		demo_login BOOLEAN NOT NULL DEFAULT false,
		status VARCHAR(20) DEFAULT 'active',
		blocked_at TIMESTAMPTZ,
		blocked_reason TEXT,
		blocked_by UUID REFERENCES users(id) ON DELETE SET NULL,
		expires_at TIMESTAMPTZ,
		-- Referral program (migration 051). Production has NO default (the app
		-- generates the code); the DEFAULT here only keeps the bare
		-- INSERT INTO users of older tests working. Hex upper still satisfies
		-- the format CHECK.
		referral_code VARCHAR(8) NOT NULL DEFAULT upper(substr(md5(random()::text), 1, 8)),
		referred_by UUID REFERENCES users(id) ON DELETE SET NULL,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW(),
		last_login_at TIMESTAMPTZ,
		deleted_at TIMESTAMPTZ,
		CONSTRAINT chk_users_referral_code CHECK (referral_code ~ '^[A-Z0-9]{8}$'),
		CONSTRAINT chk_users_not_self_referred CHECK (referred_by IS NULL OR referred_by <> id),
		CONSTRAINT chk_users_plan CHECK (plan IN ('free', 'plus', 'pro')),
		CONSTRAINT chk_users_username_formato CHECK (username IS NULL OR username ~ '^[a-z][a-z0-9._-]{2,19}$'),
		CONSTRAINT chk_users_demo_login_no_admin CHECK (NOT (demo_login AND role = 'admin'))
	);
	CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username ON users (username) WHERE username IS NOT NULL;
	-- A persisted local test DB predates the columns above (CREATE TABLE IF NOT
	-- EXISTS is a no-op there); CI always starts from an empty database.
	ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(8) NOT NULL DEFAULT upper(substr(md5(random()::text), 1, 8));
	ALTER TABLE users ADD COLUMN IF NOT EXISTS plan VARCHAR(10) NOT NULL DEFAULT 'free';
	ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(20);
	ALTER TABLE users ADD COLUMN IF NOT EXISTS demo_login BOOLEAN NOT NULL DEFAULT false;
	ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by UUID REFERENCES users(id) ON DELETE SET NULL;
	CREATE UNIQUE INDEX IF NOT EXISTS uq_users_referral_code ON users (referral_code);
	CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users (referred_by) WHERE referred_by IS NOT NULL;
	-- Same fallback for the two CHECKs: ADD COLUMN never adds constraints and
	-- Postgres has no ADD CONSTRAINT IF NOT EXISTS, so a duplicate is swallowed.
	DO $$ BEGIN
		ALTER TABLE users ADD CONSTRAINT chk_users_referral_code CHECK (referral_code ~ '^[A-Z0-9]{8}$');
	EXCEPTION WHEN duplicate_object THEN NULL; END $$;
	DO $$ BEGIN
		ALTER TABLE users ADD CONSTRAINT chk_users_not_self_referred CHECK (referred_by IS NULL OR referred_by <> id);
	EXCEPTION WHEN duplicate_object THEN NULL; END $$;
	-- Account blocking trail (migration 052) and the status CHECK (018) it
	-- relies on; same persisted-DB fallback as the referral columns above.
	ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_at     TIMESTAMPTZ;
	ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_reason TEXT;
	ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_by     UUID REFERENCES users(id) ON DELETE SET NULL;
	CREATE INDEX IF NOT EXISTS idx_users_blocked ON users (blocked_at DESC) WHERE status = 'blocked';
	DO $$ BEGIN
		ALTER TABLE users ADD CONSTRAINT chk_users_status CHECK (status IN ('active','suspended','blocked','closed'));
	EXCEPTION WHEN duplicate_object THEN NULL; END $$;
	-- Espejo de los CHECK de la 052: sin ellos una escritura incoherente
	-- (blocked sin fecha ni motivo) pasaria verde en tests y fallaria en prod.
	DO $$ BEGIN
		ALTER TABLE users ADD CONSTRAINT chk_users_blocked_reason_len
			CHECK (blocked_reason IS NULL OR char_length(blocked_reason) <= 500);
	EXCEPTION WHEN duplicate_object THEN NULL; END $$;
	DO $$ BEGIN
		ALTER TABLE users ADD CONSTRAINT chk_users_blocked_coherente CHECK (
			(status = 'blocked' AND blocked_at IS NOT NULL AND blocked_reason IS NOT NULL)
			OR (status <> 'blocked' AND blocked_at IS NULL));
	EXCEPTION WHEN duplicate_object THEN NULL; END $$;
	-- Vencimiento programado (columna en la 053, indice en la 054): mismo
	-- predicado parcial que usa el barrido, para que el plan del test sea el de
	-- produccion. Aqui va sin CONCURRENTLY porque el esquema de pruebas se crea
	-- en una sola consulta, que es de por si una transaccion.
	ALTER TABLE users ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
	CREATE INDEX IF NOT EXISTS idx_users_expires_at ON users (expires_at)
		WHERE expires_at IS NOT NULL AND status <> 'blocked' AND deleted_at IS NULL;

	CREATE TABLE IF NOT EXISTS wallets (
		id UUID PRIMARY KEY,
		user_id UUID UNIQUE NOT NULL REFERENCES users(id),
		balance_crc BIGINT DEFAULT 250000000,
		balance_usd BIGINT DEFAULT 50000,
		daily_limit BIGINT DEFAULT 100000000,
		daily_limit_usd BIGINT NOT NULL DEFAULT 19000,
		monthly_limit_usd BIGINT NOT NULL DEFAULT 95000,
		monthly_limit BIGINT DEFAULT 500000000,
		daily_spent BIGINT DEFAULT 0,
		monthly_spent BIGINT DEFAULT 0,
		status VARCHAR(20) DEFAULT 'active',
		version INT DEFAULT 1,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);
	-- Una base local persistida ya tiene la tabla creada, asi que el CREATE de
	-- arriba es un no-op ahi. Los ALTER van DESPUES de su propio CREATE: puestos
	-- junto a los de users fallaban con "relation wallets does not exist",
	-- porque esa tabla se crea mas abajo.
	ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_limit_usd BIGINT NOT NULL DEFAULT 19000;
	ALTER TABLE wallets ADD COLUMN IF NOT EXISTS monthly_limit_usd BIGINT NOT NULL DEFAULT 95000;

	CREATE TABLE IF NOT EXISTS user_sessions (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id),
		access_jti UUID,
		refresh_jti UUID,
		device_fingerprint VARCHAR(128),
		token_hash TEXT,
		refresh_token_hash TEXT,
		ip_address INET,
		user_agent TEXT,
		expires_at TIMESTAMPTZ NOT NULL,
		revoked_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS refresh_tokens (
		jti UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id),
		parent_jti UUID,
		family_id UUID NOT NULL,
		token_hash VARCHAR(128) NOT NULL,
		issued_at TIMESTAMPTZ DEFAULT NOW(),
		expires_at TIMESTAMPTZ NOT NULL,
		used_at TIMESTAMPTZ,
		revoked_at TIMESTAMPTZ,
		ip_address INET,
		user_agent TEXT
	);

	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id),
		token_hash VARCHAR(128) NOT NULL UNIQUE,
		requested_ip INET,
		expires_at TIMESTAMPTZ NOT NULL,
		used_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS mfa_challenges (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id),
		purpose VARCHAR(32) NOT NULL,
		code_hash VARCHAR(128) NOT NULL,
		metadata JSONB DEFAULT '{}',
		attempts INT DEFAULT 0,
		max_attempts INT DEFAULT 3,
		verified_at TIMESTAMPTZ,
		consumed_at TIMESTAMPTZ,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS user_totp (
		user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		secret_enc BYTEA NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT FALSE,
		last_used_step BIGINT NOT NULL DEFAULT 0,
		failed_attempts INT NOT NULL DEFAULT 0,
		locked_until TIMESTAMPTZ,
		confirmed_at TIMESTAMPTZ,
		disabled_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS totp_recovery_codes (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		code_hash VARCHAR(64) NOT NULL,
		used_at TIMESTAMPTZ,
		invalidated_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	-- Espejo de la 055 para bases de test ya persistidas.
	ALTER TABLE user_totp ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
	ALTER TABLE totp_recovery_codes ADD COLUMN IF NOT EXISTS invalidated_at TIMESTAMPTZ;

	CREATE TABLE IF NOT EXISTS transactions (
		id UUID PRIMARY KEY,
		wallet_id UUID NOT NULL,
		user_id UUID NOT NULL,
		type VARCHAR(30) NOT NULL,
		amount BIGINT NOT NULL,
		currency VARCHAR(3) DEFAULT 'CRC',
		fee BIGINT DEFAULT 0,
		counterparty_type VARCHAR(30),
		counterparty_id UUID,
		-- Must match migration 001 exactly: this column was VARCHAR(200) here
		-- while production is VARCHAR(100), so an over-long name passed the
		-- tests and only failed in production.
		counterparty_name VARCHAR(100),
		counterparty_phone VARCHAR(20),
		status VARCHAR(20) DEFAULT 'pending',
		external_reference VARCHAR(100),
		metadata JSONB DEFAULT '{}',
		idempotency_key VARCHAR(120),
		created_at TIMESTAMPTZ DEFAULT NOW(),
		processed_at TIMESTAMPTZ,
		completed_at TIMESTAMPTZ,
		created_date DATE DEFAULT CURRENT_DATE,
		UNIQUE (user_id, idempotency_key)
	);

	-- ── Ledger ──────────────────────────────────────────────────────────
	CREATE TABLE IF NOT EXISTS ledger_accounts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		code VARCHAR(64) NOT NULL UNIQUE,
		type VARCHAR(32) NOT NULL,
		user_id UUID,
		-- Mirrors migration 045: accounts owned by a shop, so business income is
		-- kept apart from the owner's personal wallet.
		merchant_id UUID,
		currency VARCHAR(3) NOT NULL,
		normal_balance VARCHAR(8) NOT NULL,
		metadata JSONB DEFAULT '{}',
		created_at TIMESTAMPTZ DEFAULT NOW()
	);
	CREATE UNIQUE INDEX IF NOT EXISTS uq_ledger_user_currency
		ON ledger_accounts (user_id, currency) WHERE type = 'user_wallet';
	CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_accounts_merchant_ccy
		ON ledger_accounts (merchant_id, currency) WHERE merchant_id IS NOT NULL;

	INSERT INTO ledger_accounts (code, type, currency, normal_balance) VALUES
		('SYSTEM:FEES:CRC',      'system_fee', 'CRC', 'credit'),
		('SYSTEM:FEES:USD',      'system_fee', 'USD', 'credit'),
		('SYSTEM:SUSPENSE:CRC',  'suspense',   'CRC', 'credit'),
		('SYSTEM:SUSPENSE:USD',  'suspense',   'USD', 'credit'),
		('SYSTEM:EXTERNAL:CRC',  'external',   'CRC', 'credit'),
		('SYSTEM:EXTERNAL:USD',  'external',   'USD', 'credit'),
		('SYSTEM:RESERVE:CRC',   'reserve',    'CRC', 'debit'),
		('SYSTEM:RESERVE:USD',   'reserve',    'USD', 'debit'),
		('SYSTEM:ESCROW:CRC',    'escrow',     'CRC', 'credit'),
		('SYSTEM:ESCROW:USD',    'escrow',     'USD', 'credit'),
		('SYSTEM:EXTERNAL:MOCK:CRC', 'external', 'CRC', 'credit'),
		('SYSTEM:EXTERNAL:MOCK:USD', 'external', 'USD', 'credit'),
		('SYSTEM:SAVINGS:CRC', 'savings', 'CRC', 'credit'),
		('SYSTEM:SAVINGS:USD', 'savings', 'USD', 'credit')
	ON CONFLICT (code) DO NOTHING;

	CREATE TABLE IF NOT EXISTS api_keys (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name VARCHAR(100) NOT NULL,
		prefix VARCHAR(16) NOT NULL,
		key_hash VARCHAR(64) NOT NULL UNIQUE,
		scopes TEXT NOT NULL DEFAULT 'escrow:read,escrow:write',
		status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
		last_used_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		revoked_at TIMESTAMP,
		expires_at TIMESTAMPTZ
	);

	CREATE TABLE IF NOT EXISTS webhook_endpoints (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		url TEXT NOT NULL,
		secret TEXT NOT NULL,
		events TEXT NOT NULL DEFAULT '*',
		status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
		created_at TIMESTAMP NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS webhook_deliveries (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
		event_type VARCHAR(64) NOT NULL,
		payload JSONB NOT NULL,
		status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','failed')),
		attempts INTEGER NOT NULL DEFAULT 0,
		next_attempt_at TIMESTAMP NOT NULL DEFAULT NOW(),
		response_code INTEGER,
		last_error TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		delivered_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS escrow_agreements (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		buyer_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
		seller_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
		amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
		currency VARCHAR(3) NOT NULL DEFAULT 'CRC' CHECK (currency IN ('CRC','USD')),
		status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN
			('pending','funded','released','refunded','disputed','cancelled')),
		description TEXT NOT NULL,
		dispute_reason TEXT,
		funded_at TIMESTAMP,
		released_at TIMESTAMP,
		refunded_at TIMESTAMP,
		disputed_at TIMESTAMP,
		cancelled_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
		settled_at TIMESTAMPTZ,
		CHECK (buyer_id <> seller_id)
	);

	CREATE TABLE IF NOT EXISTS payouts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
		rail VARCHAR(32) NOT NULL,
		amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
		currency VARCHAR(3) NOT NULL DEFAULT 'CRC' CHECK (currency IN ('CRC','USD')),
		status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN
			('pending','processing','completed','failed')),
		destination JSONB NOT NULL,
		external_id TEXT,
		failure_reason TEXT,
		idempotency_key TEXT NOT NULL,
		processing_at TIMESTAMP,
		completed_at TIMESTAMP,
		failed_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
		CONSTRAINT uq_payout_idempotency UNIQUE (user_id, idempotency_key)
	);

	CREATE TABLE IF NOT EXISTS journal_postings (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tx_id UUID,
		posted_at TIMESTAMPTZ DEFAULT NOW(),
		description TEXT NOT NULL,
		metadata JSONB DEFAULT '{}',
		idempotency_key VARCHAR(80) UNIQUE,
		created_by UUID
	);

	CREATE TABLE IF NOT EXISTS journal_entries (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		posting_id UUID NOT NULL REFERENCES journal_postings(id),
		account_id UUID NOT NULL REFERENCES ledger_accounts(id),
		direction VARCHAR(8) NOT NULL,
		amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
		currency VARCHAR(3) NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE OR REPLACE FUNCTION fn_journal_posting_balanced()
	RETURNS TRIGGER AS $$
	DECLARE
		unbalanced RECORD;
	BEGIN
		FOR unbalanced IN
			SELECT je.currency,
			       SUM(CASE WHEN je.direction='debit' THEN je.amount_minor ELSE 0 END) AS dr,
			       SUM(CASE WHEN je.direction='credit' THEN je.amount_minor ELSE 0 END) AS cr
			FROM journal_entries je
			WHERE je.posting_id = NEW.posting_id
			GROUP BY je.currency
			HAVING SUM(CASE WHEN je.direction='debit' THEN je.amount_minor ELSE 0 END)
				 <> SUM(CASE WHEN je.direction='credit' THEN je.amount_minor ELSE 0 END)
		LOOP
			RAISE EXCEPTION 'unbalanced posting %', NEW.posting_id;
		END LOOP;
		RETURN NULL;
	END;
	$$ LANGUAGE plpgsql;

	DROP TRIGGER IF EXISTS trg_journal_entries_balance ON journal_entries;
	CREATE CONSTRAINT TRIGGER trg_journal_entries_balance
		AFTER INSERT ON journal_entries
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW EXECUTE FUNCTION fn_journal_posting_balanced();

	-- Append-only enforcement — mirrors migration 020 so integration tests
	-- exercise the immutability guarantee, not just the balance trigger.
	CREATE OR REPLACE FUNCTION fn_journal_immutable()
	RETURNS TRIGGER AS $$
	BEGIN
		RAISE EXCEPTION 'journal entries are append-only (op=%, tbl=%)',
			TG_OP, TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
	END;
	$$ LANGUAGE plpgsql;

	DROP TRIGGER IF EXISTS trg_journal_entries_immutable ON journal_entries;
	CREATE TRIGGER trg_journal_entries_immutable
		BEFORE UPDATE OR DELETE ON journal_entries
		FOR EACH ROW EXECUTE FUNCTION fn_journal_immutable();

	DROP TRIGGER IF EXISTS trg_journal_postings_immutable ON journal_postings;
	CREATE TRIGGER trg_journal_postings_immutable
		BEFORE UPDATE OR DELETE ON journal_postings
		FOR EACH ROW EXECUTE FUNCTION fn_journal_immutable();

	CREATE OR REPLACE VIEW ledger_account_balances AS
	SELECT la.id AS account_id, la.code, la.type, la.user_id, la.currency, la.normal_balance,
		COALESCE(SUM(CASE WHEN je.direction='debit' THEN je.amount_minor ELSE 0 END), 0) AS total_debit,
		COALESCE(SUM(CASE WHEN je.direction='credit' THEN je.amount_minor ELSE 0 END), 0) AS total_credit,
		CASE la.normal_balance
			WHEN 'debit'  THEN COALESCE(SUM(CASE WHEN je.direction='debit'  THEN je.amount_minor ELSE -je.amount_minor END), 0)
			WHEN 'credit' THEN COALESCE(SUM(CASE WHEN je.direction='credit' THEN je.amount_minor ELSE -je.amount_minor END), 0)
		END AS balance_minor
	FROM ledger_accounts la
	LEFT JOIN journal_entries je ON je.account_id = la.id
	GROUP BY la.id, la.code, la.type, la.user_id, la.currency, la.normal_balance;

	CREATE OR REPLACE VIEW wallet_journal_drift AS
	SELECT w.user_id,
		w.balance_crc AS cache_crc,
		COALESCE(crc.balance_minor, 0) AS journal_crc,
		(w.balance_crc - COALESCE(crc.balance_minor, 0)) AS drift_crc,
		w.balance_usd AS cache_usd,
		COALESCE(usd.balance_minor, 0) AS journal_usd,
		(w.balance_usd - COALESCE(usd.balance_minor, 0)) AS drift_usd
	FROM wallets w
	LEFT JOIN ledger_account_balances crc ON crc.user_id = w.user_id AND crc.currency='CRC'
	LEFT JOIN ledger_account_balances usd ON usd.user_id = w.user_id AND usd.currency='USD';

	-- Other domains (kept minimal for cross-package tests)
	CREATE TABLE IF NOT EXISTS sinpe_contacts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id),
		phone VARCHAR(20) NOT NULL,
		name VARCHAR(200) NOT NULL,
		bank VARCHAR(100),
		is_favorite BOOLEAN DEFAULT false,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		UNIQUE(user_id, phone)
	);

	CREATE TABLE IF NOT EXISTS sinpe_history (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL,
		phone VARCHAR(20) NOT NULL,
		contact_name VARCHAR(200),
		amount BIGINT NOT NULL,
		fee BIGINT DEFAULT 0,
		type VARCHAR(10) NOT NULL,
		status VARCHAR(20) DEFAULT 'completed',
		description TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	-- Crypto (NUMERIC precision per migration 019).
	CREATE TABLE IF NOT EXISTS crypto_assets (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL,
		symbol VARCHAR(20) NOT NULL,
		name VARCHAR(100) NOT NULL,
		balance NUMERIC(38,18) DEFAULT 0,
		avg_cost NUMERIC(38,18) DEFAULT 0,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW(),
		UNIQUE(user_id, symbol)
	);

	CREATE TABLE IF NOT EXISTS crypto_transactions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL,
		type VARCHAR(20) NOT NULL,
		asset VARCHAR(40) NOT NULL,
		amount NUMERIC(38,18) NOT NULL,
		price NUMERIC(38,18) DEFAULT 0,
		total NUMERIC(38,18) DEFAULT 0,
		currency VARCHAR(10) NOT NULL,
		fee NUMERIC(38,18) DEFAULT 0,
		status VARCHAR(20) DEFAULT 'completed',
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS crypto_staking (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL,
		asset VARCHAR(20) NOT NULL,
		amount NUMERIC(38,18) NOT NULL,
		apy NUMERIC(8,4) DEFAULT 0,
		start_date TIMESTAMPTZ DEFAULT NOW(),
		locked BOOLEAN DEFAULT false,
		lock_days INT DEFAULT 0,
		earned NUMERIC(38,18) DEFAULT 0,
		status VARCHAR(20) DEFAULT 'active',
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS crypto_price_alerts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL,
		asset VARCHAR(20) NOT NULL,
		target_price NUMERIC(38,18) NOT NULL,
		direction VARCHAR(10) NOT NULL,
		active BOOLEAN DEFAULT true,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	-- KYC / AML (migration 025).
	CREATE TABLE IF NOT EXISTS kyc_verifications (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id),
		level_requested INTEGER NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'pending',
		full_legal_name VARCHAR(200) NOT NULL,
		birth_date DATE,
		nationality VARCHAR(2),
		document_type VARCHAR(30) NOT NULL,
		document_number VARCHAR(60) NOT NULL,
		screening_result VARCHAR(20) NOT NULL DEFAULT 'pending',
		reviewer_notes TEXT,
		decided_by UUID REFERENCES users(id),
		submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		decided_at TIMESTAMPTZ
	);

	CREATE TABLE IF NOT EXISTS kyc_documents (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		verification_id UUID NOT NULL REFERENCES kyc_verifications(id) ON DELETE CASCADE,
		doc_type VARCHAR(30) NOT NULL,
		file_ref TEXT NOT NULL,
		sha256 VARCHAR(64),
		uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS sanction_list (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		source VARCHAR(20) NOT NULL,
		full_name VARCHAR(200) NOT NULL,
		normalized_name VARCHAR(200) NOT NULL,
		birth_date DATE,
		nationality VARCHAR(2),
		program VARCHAR(100),
		added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS sanction_screenings (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID REFERENCES users(id),
		verification_id UUID REFERENCES kyc_verifications(id) ON DELETE SET NULL,
		query_name VARCHAR(200) NOT NULL,
		normalized_query VARCHAR(200) NOT NULL,
		result VARCHAR(20) NOT NULL,
		match_count INTEGER NOT NULL DEFAULT 0,
		matched_ids TEXT,
		screened_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS uif_reports (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id),
		tx_id UUID,
		report_type VARCHAR(20) NOT NULL,
		amount_minor BIGINT NOT NULL,
		currency VARCHAR(10) NOT NULL,
		daily_total_minor BIGINT NOT NULL DEFAULT 0,
		reason TEXT NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'pending',
		reviewer_id UUID REFERENCES users(id),
		reviewer_notes TEXT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		reviewed_at TIMESTAMPTZ
	);
	CREATE UNIQUE INDEX IF NOT EXISTS uq_uif_reports_tx_single
		ON uif_reports(tx_id, report_type) WHERE tx_id IS NOT NULL;

	-- Fraud (migration 010).
	CREATE TABLE IF NOT EXISTS fraud_rules (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(200) NOT NULL,
		description TEXT DEFAULT '',
		category VARCHAR(30) NOT NULL,
		condition JSONB NOT NULL,
		score_weight INTEGER NOT NULL,
		active BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS fraud_assessments (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		tx_type VARCHAR(30) NOT NULL,
		tx_id VARCHAR(100) NOT NULL,
		amount BIGINT NOT NULL,
		risk_score INTEGER NOT NULL,
		risk_level VARCHAR(20) NOT NULL,
		factors TEXT NOT NULL,
		action VARCHAR(20) NOT NULL,
		reviewed_by VARCHAR(100),
		reviewed_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS fraud_alerts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		assessment_id UUID NOT NULL REFERENCES fraud_assessments(id),
		type VARCHAR(30) NOT NULL,
		severity VARCHAR(20) NOT NULL,
		message TEXT NOT NULL,
		status VARCHAR(20) DEFAULT 'open',
		resolved_by VARCHAR(100),
		resolved_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS user_risk_profiles (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
		overall_risk_score INTEGER DEFAULT 0,
		total_transactions BIGINT DEFAULT 0,
		total_flagged BIGINT DEFAULT 0,
		avg_tx_amount BIGINT DEFAULT 0,
		max_tx_amount BIGINT DEFAULT 0,
		last_activity_at TIMESTAMP DEFAULT NOW(),
		account_age_days INTEGER DEFAULT 0,
		is_restricted BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);

	INSERT INTO sanction_list (source, full_name, normalized_name, nationality, program)
	SELECT v.source, v.full_name, v.normalized_name, v.nationality, v.program
	FROM (VALUES
		('OFAC', 'Carlos Sancion Prueba',      'carlos sancion prueba',      'CR', 'SDN-TEST'),
		('UN',   'Ivan Testovich Blocklisted', 'ivan testovich blocklisted', 'RU', 'UNSC-TEST')
	) AS v(source, full_name, normalized_name, nationality, program)
	WHERE NOT EXISTS (SELECT 1 FROM sanction_list);

	-- QR merchant payment tables (migrations 007 + 038). FKs use ON DELETE CASCADE
	-- so the truncate-on-each-test cleanup cascades cleanly.
	CREATE TABLE IF NOT EXISTS qr_merchants (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name VARCHAR(200) NOT NULL,
		description TEXT DEFAULT '',
		category VARCHAR(30) NOT NULL,
		logo_url VARCHAR(500),
		qr_code VARCHAR(50) NOT NULL UNIQUE,
		active BOOLEAN DEFAULT TRUE,
		cedula VARCHAR(50) NOT NULL DEFAULT '',
		cedula_type VARCHAR(20) NOT NULL DEFAULT 'fisica',
		legal_name VARCHAR(200) NOT NULL DEFAULT '',
		verification_status VARCHAR(20) NOT NULL DEFAULT 'pending',
		reviewed_at TIMESTAMP,
		reviewed_by UUID REFERENCES users(id),
		rejection_reason TEXT NOT NULL DEFAULT '',
		commission_bps INTEGER NOT NULL DEFAULT 50,
		created_at TIMESTAMP DEFAULT NOW()
	);

	-- Phase 3 of business mode (migration 046): locations, staff, catalog.
	CREATE TABLE IF NOT EXISTS merchant_locations (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		merchant_id UUID NOT NULL REFERENCES qr_merchants(id) ON DELETE CASCADE,
		name VARCHAR(120) NOT NULL,
		address VARCHAR(300) NOT NULL DEFAULT '',
		active BOOLEAN NOT NULL DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS merchant_staff (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		merchant_id UUID NOT NULL REFERENCES qr_merchants(id) ON DELETE CASCADE,
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		role VARCHAR(20) NOT NULL DEFAULT 'cashier',
		status VARCHAR(20) NOT NULL DEFAULT 'active',
		location_id UUID REFERENCES merchant_locations(id) ON DELETE SET NULL,
		added_by UUID NOT NULL REFERENCES users(id),
		created_at TIMESTAMP DEFAULT NOW(),
		revoked_at TIMESTAMP,
		CONSTRAINT chk_merchant_staff_role   CHECK (role IN ('cashier','manager')),
		CONSTRAINT chk_merchant_staff_status CHECK (status IN ('active','revoked')),
		CONSTRAINT uq_merchant_staff_member  UNIQUE (merchant_id, user_id)
	);

	CREATE TABLE IF NOT EXISTS merchant_catalog_items (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		merchant_id UUID NOT NULL REFERENCES qr_merchants(id) ON DELETE CASCADE,
		name VARCHAR(120) NOT NULL,
		price_minor BIGINT NOT NULL,
		currency VARCHAR(10) NOT NULL DEFAULT 'CRC',
		active BOOLEAN NOT NULL DEFAULT TRUE,
		sort_order INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP DEFAULT NOW(),
		CONSTRAINT chk_catalog_price_positive CHECK (price_minor > 0)
	);

	CREATE TABLE IF NOT EXISTS qr_payment_codes (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		type VARCHAR(30) NOT NULL,
		amount BIGINT DEFAULT 0,
		currency VARCHAR(10) DEFAULT 'CRC',
		merchant_id UUID REFERENCES qr_merchants(id) ON DELETE CASCADE,
		note TEXT,
		qr_data TEXT NOT NULL UNIQUE,
		single_use BOOLEAN DEFAULT FALSE,
		used BOOLEAN DEFAULT FALSE,
		expires_at TIMESTAMP,
		location_id UUID REFERENCES merchant_locations(id) ON DELETE SET NULL,
		created_at TIMESTAMP DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS qr_payments (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		qr_code_id UUID NOT NULL REFERENCES qr_payment_codes(id) ON DELETE CASCADE,
		payer_id UUID NOT NULL REFERENCES users(id),
		receiver_id UUID NOT NULL REFERENCES users(id),
		merchant_id UUID REFERENCES qr_merchants(id) ON DELETE CASCADE,
		amount BIGINT NOT NULL,
		fee BIGINT NOT NULL DEFAULT 0,
		currency VARCHAR(10) DEFAULT 'CRC',
		status VARCHAR(20) DEFAULT 'pending',
		note TEXT,
		tx_id VARCHAR(100),
		location_id UUID REFERENCES merchant_locations(id) ON DELETE SET NULL,
		collected_by UUID REFERENCES users(id) ON DELETE SET NULL,
		created_at TIMESTAMP DEFAULT NOW(),
		completed_at TIMESTAMP
	);

	-- Minimal service_providers (migration 001) — just the columns PayBill reads.
	CREATE TABLE IF NOT EXISTS service_providers (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		code VARCHAR(20) UNIQUE NOT NULL,
		name VARCHAR(100) NOT NULL,
		category VARCHAR(50) NOT NULL DEFAULT 'telecom',
		is_active BOOLEAN DEFAULT TRUE
	);

	-- Marketplace (migration 005)
	CREATE TABLE IF NOT EXISTS marketplace_partners (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		code VARCHAR(50) NOT NULL UNIQUE,
		name VARCHAR(100) NOT NULL,
		category VARCHAR(30) NOT NULL,
		logo VARCHAR(100) DEFAULT '',
		color VARCHAR(20) DEFAULT '#000000',
		description TEXT DEFAULT '',
		active BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS user_partner_connections (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		partner_code VARCHAR(50) NOT NULL REFERENCES marketplace_partners(code),
		connected_at TIMESTAMP DEFAULT NOW(),
		UNIQUE(user_id, partner_code)
	);
	CREATE TABLE IF NOT EXISTS ride_requests (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		partner_code VARCHAR(50) NOT NULL,
		pickup TEXT NOT NULL,
		destination TEXT NOT NULL,
		estimated_price BIGINT NOT NULL,
		estimated_time VARCHAR(30) NOT NULL,
		distance VARCHAR(30) NOT NULL,
		status VARCHAR(20) DEFAULT 'searching',
		driver_name VARCHAR(100),
		driver_rating DOUBLE PRECISION,
		driver_car VARCHAR(100),
		driver_plate VARCHAR(20),
		final_price BIGINT,
		created_at TIMESTAMP DEFAULT NOW(),
		completed_at TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS food_orders (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		partner_code VARCHAR(50) NOT NULL,
		restaurant_name VARCHAR(200) NOT NULL,
		subtotal BIGINT NOT NULL,
		delivery_fee BIGINT NOT NULL,
		total BIGINT NOT NULL,
		status VARCHAR(20) DEFAULT 'preparing',
		estimated_delivery VARCHAR(30) NOT NULL,
		created_at TIMESTAMP DEFAULT NOW(),
		completed_at TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS food_order_items (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		order_id UUID NOT NULL REFERENCES food_orders(id) ON DELETE CASCADE,
		name VARCHAR(200) NOT NULL,
		quantity INTEGER NOT NULL DEFAULT 1,
		price BIGINT NOT NULL
	);

	-- Loyalty (migration 006, points account + history) and the referral-bonus
	-- idempotency index (migration 051). GrantBonusOnce relies on
	-- uq_loyalty_tx_referral: without it ON CONFLICT DO NOTHING has nothing to
	-- hit and the bonus would be credited twice.
	CREATE TABLE IF NOT EXISTS loyalty_accounts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
		total_points BIGINT DEFAULT 0,
		available_points BIGINT DEFAULT 0,
		lifetime_points BIGINT DEFAULT 0,
		tier VARCHAR(20) DEFAULT 'bronze',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS loyalty_transactions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		type VARCHAR(20) NOT NULL,
		points BIGINT NOT NULL,
		description TEXT DEFAULT '',
		ref_type VARCHAR(30),
		ref_id VARCHAR(100),
		created_at TIMESTAMPTZ DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_loyalty_tx_user ON loyalty_transactions(user_id, created_at DESC);
	CREATE UNIQUE INDEX IF NOT EXISTS uq_loyalty_tx_referral
		ON loyalty_transactions (ref_id) WHERE ref_type = 'referral';

	CREATE TABLE IF NOT EXISTS savings_goals (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name VARCHAR(120) NOT NULL,
		target_minor BIGINT NOT NULL,
		saved_minor BIGINT NOT NULL DEFAULT 0,
		currency VARCHAR(3) NOT NULL DEFAULT 'CRC',
		icon VARCHAR(40) NOT NULL DEFAULT 'piggy-bank',
		color VARCHAR(20) NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- Interest in a paid plan (migration 056). Not a subscription: nothing
	-- charges. The unique index is what makes registering twice one row.
	CREATE TABLE IF NOT EXISTS plan_interest (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		plan VARCHAR(16) NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT chk_plan_interest_plan CHECK (plan IN ('negocio', 'cima'))
	);
	CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_interest_user_plan
		ON plan_interest (user_id, plan);
	CREATE INDEX IF NOT EXISTS idx_plan_interest_created
		ON plan_interest (created_at DESC);

	-- Audit trail (migration 023, partitioned there; flat here). No FK to
	-- users, like production. details is plain JSONB: never PII.
	CREATE TABLE IF NOT EXISTS audit_logs (
		id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id       UUID,
		action        VARCHAR(64) NOT NULL,
		resource_type VARCHAR(64),
		resource_id   TEXT,
		ip_address    INET,
		user_agent    TEXT,
		details       JSONB DEFAULT '{}',
		risk_level    VARCHAR(16),
		created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		created_date  DATE NOT NULL DEFAULT CURRENT_DATE
	);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action, created_at DESC);
	`

	if _, err := pool.Exec(ctx, schema); err != nil {
		return err
	}
	// Mirror migration 034: convert any naive TIMESTAMP column to TIMESTAMPTZ so
	// the test schema matches production and is immune to the DB server timezone.
	_, err := pool.Exec(ctx, `
	DO $$
	DECLARE r RECORD;
	BEGIN
		FOR r IN
			SELECT c.table_name, c.column_name
			FROM information_schema.columns c
			JOIN information_schema.tables t
				ON t.table_schema = c.table_schema AND t.table_name = c.table_name
			WHERE c.table_schema = 'public'
				AND t.table_type = 'BASE TABLE'
				AND c.data_type = 'timestamp without time zone'
		LOOP
			EXECUTE format(
				'ALTER TABLE public.%I ALTER COLUMN %I TYPE timestamptz USING %I AT TIME ZONE ''UTC''',
				r.table_name, r.column_name, r.column_name);
		END LOOP;
	END $$;`)
	return err
}

func truncateAll(ctx context.Context, pool *pgxpool.Pool) error {
	tables := []string{
		"sinpe_history", "sinpe_contacts",
		"crypto_price_alerts", "crypto_staking", "crypto_transactions", "crypto_assets",
		"uif_reports",
		"fraud_alerts", "fraud_assessments", "user_risk_profiles", "fraud_rules",
		"sanction_screenings", "kyc_documents", "kyc_verifications",
		"webhook_deliveries", "webhook_endpoints", "api_keys",
		"escrow_agreements",
		"payouts",
		"merchant_staff", "merchant_catalog_items", "merchant_locations",
		"qr_payments", "qr_payment_codes", "qr_merchants",
		"service_providers",
		"food_order_items", "food_orders", "ride_requests",
		"user_partner_connections", "marketplace_partners",
		"savings_goals",
		"plan_interest",
		"loyalty_transactions", "loyalty_accounts",
		"journal_entries", "journal_postings",
		"transactions",
		"totp_recovery_codes", "user_totp",
		"mfa_challenges", "password_reset_tokens", "refresh_tokens",
		"user_sessions", "wallets",
		"ledger_accounts",
		"audit_logs",
		"users",
	}
	for _, tbl := range tables {
		if _, err := pool.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", tbl)); err != nil { //nolint:gosec // test-only, fixed table list
			return fmt.Errorf("truncate %s: %w", tbl, err)
		}
	}
	// Re-seed system ledger accounts after truncate.
	if _, err := pool.Exec(ctx, `
		INSERT INTO ledger_accounts (code, type, currency, normal_balance) VALUES
			('SYSTEM:FEES:CRC',      'system_fee', 'CRC', 'credit'),
			('SYSTEM:FEES:USD',      'system_fee', 'USD', 'credit'),
			('SYSTEM:SUSPENSE:CRC',  'suspense',   'CRC', 'credit'),
			('SYSTEM:SUSPENSE:USD',  'suspense',   'USD', 'credit'),
			('SYSTEM:EXTERNAL:CRC',  'external',   'CRC', 'credit'),
			('SYSTEM:EXTERNAL:USD',  'external',   'USD', 'credit'),
			('SYSTEM:RESERVE:CRC',   'reserve',    'CRC', 'debit'),
			('SYSTEM:RESERVE:USD',   'reserve',    'USD', 'debit'),
			('SYSTEM:ESCROW:CRC',    'escrow',     'CRC', 'credit'),
			('SYSTEM:ESCROW:USD',    'escrow',     'USD', 'credit'),
			('SYSTEM:SAVINGS:CRC',   'savings',    'CRC', 'credit'),
			('SYSTEM:SAVINGS:USD',   'savings',    'USD', 'credit'),
			('SYSTEM:EXTERNAL:MOCK:CRC', 'external', 'CRC', 'credit'),
			('SYSTEM:EXTERNAL:MOCK:USD', 'external', 'USD', 'credit')
		ON CONFLICT (code) DO NOTHING
	`); err != nil {
		return fmt.Errorf("re-seed system ledger accounts: %w", err)
	}
	return nil
}

// SeedTestUser creates a test user with wallet and returns the user ID.
func SeedTestUser(t *testing.T, pool *pgxpool.Pool, cedula, passwordHash string) string {
	t.Helper()

	userID := "00000000-0000-0000-0000-000000000001"
	walletID := "00000000-0000-0000-0000-000000000101"

	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, cedula_enc, cedula_hash, phone_enc, phone_hash, first_name, last_name, password_hash, status, kyc_level)
		 VALUES ($1, fn_pii_encrypt($2), fn_pii_hmac($2), fn_pii_encrypt('+50688881234'), fn_pii_hmac('+50688881234'), 'Test', 'User', $3, 'active', 1)
		 ON CONFLICT (id) DO NOTHING`,
		userID, cedula, passwordHash,
	); err != nil {
		t.Fatalf("Failed to seed test user: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO wallets (id, user_id, balance_crc, balance_usd)
		 VALUES ($1, $2, 250000000, 50000)
		 ON CONFLICT (user_id) DO NOTHING`,
		walletID, userID,
	); err != nil {
		t.Fatalf("Failed to seed test wallet: %v", err)
	}

	// Provision ledger accounts for this user.
	if _, err := pool.Exec(ctx,
		`INSERT INTO ledger_accounts (code, type, user_id, currency, normal_balance)
		 VALUES ('USER:'||$1||':CRC','user_wallet',$1::uuid,'CRC','credit'),
		        ('USER:'||$1||':USD','user_wallet',$1::uuid,'USD','credit')
		 ON CONFLICT (code) DO NOTHING`,
		userID,
	); err != nil {
		t.Fatalf("provision ledger accounts: %v", err)
	}

	// Seed opening balance in the journal so reconciliation matches.
	postID := "00000000-0000-0000-0000-000000000abc"
	_, _ = pool.Exec(ctx,
		`INSERT INTO journal_postings (id, description) VALUES ($1::uuid,'SEED_OPENING')
		 ON CONFLICT DO NOTHING`,
		postID,
	)
	_, _ = pool.Exec(ctx, `
		INSERT INTO journal_entries (posting_id, account_id, direction, amount_minor, currency)
		SELECT $1::uuid, la.id, 'credit', 250000000, 'CRC'
		FROM ledger_accounts la WHERE la.user_id = $2::uuid AND la.currency='CRC'`,
		postID, userID,
	)
	_, _ = pool.Exec(ctx, `
		INSERT INTO journal_entries (posting_id, account_id, direction, amount_minor, currency)
		SELECT $1::uuid, la.id, 'debit', 250000000, 'CRC'
		FROM ledger_accounts la WHERE la.code='SYSTEM:RESERVE:CRC'`,
		postID,
	)

	return userID
}

// SeedTestUser2 creates a second test user for transfer tests.
func SeedTestUser2(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()

	userID := "00000000-0000-0000-0000-000000000002"
	walletID := "00000000-0000-0000-0000-000000000102"

	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, cedula_enc, cedula_hash, phone_enc, phone_hash, first_name, last_name, password_hash, status, kyc_level, role)
		 VALUES ($1, fn_pii_encrypt('700000000'), fn_pii_hmac('700000000'), fn_pii_encrypt('+50688885678'), fn_pii_hmac('+50688885678'), 'Admin', 'User', 'dummy_hash', 'active', 1, 'admin')
		 ON CONFLICT (id) DO NOTHING`,
		userID,
	); err != nil {
		t.Fatalf("Failed to seed test user 2: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO wallets (id, user_id, balance_crc, balance_usd)
		 VALUES ($1, $2, 100000000, 20000)
		 ON CONFLICT (user_id) DO NOTHING`,
		walletID, userID,
	); err != nil {
		t.Fatalf("Failed to seed test wallet 2: %v", err)
	}

	_, _ = pool.Exec(ctx,
		`INSERT INTO ledger_accounts (code, type, user_id, currency, normal_balance)
		 VALUES ('USER:'||$1||':CRC','user_wallet',$1::uuid,'CRC','credit'),
		        ('USER:'||$1||':USD','user_wallet',$1::uuid,'USD','credit')
		 ON CONFLICT (code) DO NOTHING`,
		userID,
	)

	postID := "00000000-0000-0000-0000-000000000def"
	_, _ = pool.Exec(ctx,
		`INSERT INTO journal_postings (id, description) VALUES ($1::uuid,'SEED_OPENING_U2')
		 ON CONFLICT DO NOTHING`,
		postID,
	)
	_, _ = pool.Exec(ctx, `
		INSERT INTO journal_entries (posting_id, account_id, direction, amount_minor, currency)
		SELECT $1::uuid, la.id, 'credit', 100000000, 'CRC'
		FROM ledger_accounts la WHERE la.user_id = $2::uuid AND la.currency='CRC'`,
		postID, userID,
	)
	_, _ = pool.Exec(ctx, `
		INSERT INTO journal_entries (posting_id, account_id, direction, amount_minor, currency)
		SELECT $1::uuid, la.id, 'debit', 100000000, 'CRC'
		FROM ledger_accounts la WHERE la.code='SYSTEM:RESERVE:CRC'`,
		postID,
	)

	return userID
}
