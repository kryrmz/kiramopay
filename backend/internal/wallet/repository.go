package wallet

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kiramopay/backend/internal/kyc"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateForUser(ctx context.Context, userID string) error {
	// New users start at KYC level 0 (Basic). Pin the wallet limits to that tier
	// explicitly instead of relying on the column default: migration 001 defaults
	// daily/monthly_limit to the higher "Verified" tier, which would silently let
	// an unverified account transact well above its intended cap.
	basic := kyc.LevelLimits[kyc.LevelBasic]
	_, err := r.db.Exec(ctx,
		`INSERT INTO wallets (id, user_id, daily_limit, monthly_limit, daily_limit_usd, monthly_limit_usd)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New().String(), userID, basic.DailyMinor, basic.MonthlyMinor,
		basic.DailyMinorUSD, basic.MonthlyMinorUSD,
	)
	if err != nil {
		return fmt.Errorf("create wallet: %w", err)
	}
	return nil
}

func (r *Repository) FindByUserID(ctx context.Context, userID string) (*WalletRecord, error) {
	w := &WalletRecord{}
	err := r.db.QueryRow(ctx,
		`SELECT id, user_id, balance_crc, balance_usd, daily_limit, monthly_limit,
		        daily_limit_usd, monthly_limit_usd,
		        daily_spent, monthly_spent, status, version, created_at, updated_at
		 FROM wallets WHERE user_id = $1`,
		userID,
	).Scan(
		&w.ID, &w.UserID, &w.BalanceCRC, &w.BalanceUSD, &w.DailyLimit, &w.MonthlyLimit,
		&w.DailyLimitUSD, &w.MonthlyLimitUSD,
		&w.DailySpent, &w.MonthlySpent, &w.Status, &w.Version, &w.CreatedAt, &w.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("find wallet: %w", err)
	}
	return w, nil
}

func (r *Repository) UpdateBalance(ctx context.Context, walletID string, amountCRC, amountUSD int64, currentVersion int) error {
	result, err := r.db.Exec(ctx,
		`UPDATE wallets
		 SET balance_crc = balance_crc + $2,
		     balance_usd = balance_usd + $3,
		     version = version + 1,
		     updated_at = NOW()
		 WHERE id = $1 AND version = $4`,
		walletID, amountCRC, amountUSD, currentVersion,
	)
	if err != nil {
		return fmt.Errorf("update balance: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("optimistic lock conflict: wallet was modified concurrently")
	}
	return nil
}
