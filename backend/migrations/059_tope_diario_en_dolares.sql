-- El tope diario de gasto, tambien en dolares.
--
-- `wallets.daily_limit` esta en CENTIMOS DE COLON: los valores por nivel de KYC
-- son 10.000.000 = 100.000 colones para una cuenta basica. Pero la
-- comprobacion lo comparaba contra el monto de la operacion SIN mirar la
-- moneda, asi que una salida en dolares se medía contra un tope en colones:
-- USD 5.000 son 500.000 centimos, muy por debajo de 10.000.000, y pasaba. El
-- tope que se queria aplicar equivale a unos USD 190, asi que en dolares no
-- frenaba nada — ni en transferencias ni en el escrow.
--
-- El propio repositorio ya resuelve esto bien en el otro control del mismo
-- tipo: mfa tiene umbrales separados para CRC y USD. Esto lo espeja.
ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_limit_usd   BIGINT NOT NULL DEFAULT 19000;
ALTER TABLE wallets ADD COLUMN IF NOT EXISTS monthly_limit_usd BIGINT NOT NULL DEFAULT 95000;

DO $$
BEGIN
    ALTER TABLE wallets ADD CONSTRAINT chk_wallet_daily_limit_usd_pos CHECK (daily_limit_usd >= 0);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE wallets ADD CONSTRAINT chk_wallet_monthly_limit_usd_pos CHECK (monthly_limit_usd >= 0);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Backfill por nivel de KYC, con los mismos tramos que kyc.LevelLimits. No se
-- convierte desde el tope en colones con un tipo de cambio: el que hay en la
-- base esta congelado desde su semilla y derivar un tope de el seria heredar
-- ese problema. Los valores son deliberados y redondos.
UPDATE wallets w
   SET daily_limit_usd   = CASE COALESCE(u.kyc_level, 0)
                             WHEN 2 THEN 380000   -- USD 3.800
                             WHEN 1 THEN 95000    -- USD   950
                             ELSE        19000    -- USD   190
                           END,
       monthly_limit_usd = CASE COALESCE(u.kyc_level, 0)
                             WHEN 2 THEN 3800000  -- USD 38.000
                             WHEN 1 THEN 950000   -- USD  9.500
                             ELSE        95000    -- USD    950
                           END,
       updated_at = NOW()
  FROM users u
 WHERE u.id = w.user_id;
