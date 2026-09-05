ALTER TABLE wallets DROP CONSTRAINT IF EXISTS chk_wallet_daily_limit_usd_pos;
ALTER TABLE wallets DROP CONSTRAINT IF EXISTS chk_wallet_monthly_limit_usd_pos;
ALTER TABLE wallets DROP COLUMN IF EXISTS daily_limit_usd;
ALTER TABLE wallets DROP COLUMN IF EXISTS monthly_limit_usd;
