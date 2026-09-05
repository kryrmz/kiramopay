package wallet

import "time"

type WalletRecord struct {
	ID               string    `json:"id"`
	UserID           string    `json:"user_id"`
	BalanceCRC       int64     `json:"balance_crc"`
	BalanceUSD       int64     `json:"balance_usd"`
	// En centimos de COLON.
	DailyLimit   int64 `json:"daily_limit"`
	MonthlyLimit int64 `json:"monthly_limit"`
	// En centimos de DOLAR. Un tope por moneda, no uno convertido: comparar un
	// monto en dolares contra el tope en colones no frena nada.
	DailyLimitUSD   int64 `json:"daily_limit_usd"`
	MonthlyLimitUSD int64 `json:"monthly_limit_usd"`
	DailySpent       int64     `json:"daily_spent"`
	MonthlySpent     int64     `json:"monthly_spent"`
	Status           string    `json:"status"`
	Version          int       `json:"version"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type BalanceResponse struct {
	CRC          int64  `json:"crc"`
	USD          int64  `json:"usd"`
	CRCFormatted string `json:"crc_formatted"`
	USDFormatted string `json:"usd_formatted"`
}
