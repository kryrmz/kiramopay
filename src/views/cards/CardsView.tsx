import React, { useCallback, useEffect, useState } from 'react';
import { useLanguage } from '../../i18n/LanguageContext';
import { Icons } from '../../components/Icons';
import { Button } from '../../components/ui';
import { BottomSheet } from '../../components/BottomSheet';
import { getApiLayer } from '@/api';
import type { VirtualCard } from '@/api/repositories/cards.repository';

export const CardsView: React.FC = () => {
  const { t } = useLanguage();
  const api = getApiLayer().cards;

  const [cards, setCards] = useState<VirtualCard[]>([]);
  // Distinguir "no pude preguntar" de "no hay tarjetas". Sin esto, un fallo de
  // red pintaba el estado vacio -"todavia no tienes tarjetas"- a alguien que si
  // tiene una, invitandolo a crear una segunda.
  const [loadFailed, setLoadFailed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  const [showLimits, setShowLimits] = useState(false);
  const [showReveal, setShowReveal] = useState(false);
  const [showCancel, setShowCancel] = useState(false);
  // Full PAN + CVV are returned by the backend ONLY on creation; keep them in
  // memory to show once and never persist them.
  const [revealed, setRevealed] = useState<VirtualCard | null>(null);
  const [tempDaily, setTempDaily] = useState(0);
  const [tempAtm, setTempAtm] = useState(0);

  // Reusable refresh for event handlers (after create/freeze/limits/cancel).
  const load = useCallback(async () => {
    if (!api) { setLoading(false); return; }
    const res = await api.getCards();
    if (res.success && res.data) {
      setCards(res.data.filter((c) => c.status !== 'cancelled'));
      setLoadFailed(false);
    } else {
      setLoadFailed(true);
    }
    setLoading(false);
  }, [api]);

  // Initial fetch — setState lives inside the async body (not the effect body).
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!api) { if (!cancelled) setLoading(false); return; }
      const res = await api.getCards();
      if (!cancelled) {
        if (res.success && res.data) {
          setCards(res.data.filter((c) => c.status !== 'cancelled'));
          setLoadFailed(false);
        } else {
          setLoadFailed(true);
        }
        setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [api]);

  const card = cards[0];
  const frozen = card?.status === 'frozen';

  const formatCRC = (n: number) =>
    new Intl.NumberFormat('en-US', { style: 'currency', currencyDisplay: 'narrowSymbol', currency: 'CRC', maximumFractionDigits: 0 }).format(n);

  const handleCreate = async () => {
    if (!api || busy) return;
    setBusy(true);
    setError('');
    const res = await api.createCard({ type: 'virtual', currency: 'CRC' });
    setBusy(false);
    if (!res.success || !res.data) {
      setError(res.error?.message || t('assistant_action_failed'));
      return;
    }
    setRevealed(res.data);
    setShowReveal(true);
    await load();
  };

  const handleFreeze = async () => {
    if (!api || !card || busy) return;
    setBusy(true);
    setError('');
    const res = await api.freezeCard(card.id, !frozen);
    setBusy(false);
    if (res.success) await load();
    else setError(res.error?.message || t('assistant_action_failed'));
  };

  const openLimits = () => {
    if (!card) return;
    setTempDaily(card.dailyLimit);
    setTempAtm(card.atmLimit);
    setShowLimits(true);
  };

  const saveLimits = async () => {
    if (!api || !card || busy) return;
    setBusy(true);
    setError('');
    const res = await api.updateLimits(card.id, { dailyLimit: tempDaily, atmLimit: tempAtm });
    setBusy(false);
    if (res.success) { await load(); setShowLimits(false); }
    else setError(res.error?.message || t('assistant_action_failed'));
  };

  const confirmCancel = async () => {
    if (!api || !card || busy) return;
    setBusy(true);
    setError('');
    const res = await api.cancelCard(card.id);
    setBusy(false);
    setShowCancel(false);
    if (res.success) await load();
    else setError(res.error?.message || t('assistant_action_failed'));
  };

  const copyNumber = async () => {
    if (!revealed) return;
    try {
      await navigator.clipboard.writeText(revealed.cardNumber.replace(/\s/g, ''));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard unavailable — ignore
    }
  };

  const groupPan = (pan: string) => pan.replace(/\s/g, '').replace(/(.{4})/g, '$1 ').trim();

  return (
    <div className="pt-4 px-4 pb-24 space-y-6">
      {loading ? (
        <div className="h-56 w-full max-w-md mx-auto rounded-3xl bg-[var(--color-surface-muted)] dark:bg-[var(--color-surface-muted-dark)] animate-pulse" />
      ) : !card && loadFailed ? (
        /* No se pudo consultar. Ofrecer "crear tarjeta" aqui seria empujar a
           crear una segunda a quien ya tiene la suya. */
        <div className="uv-surface-1 rounded-3xl p-8 text-center uv-shadow-soft">
          <div className="w-16 h-16 rounded-2xl bg-[var(--color-danger-soft,var(--color-surface-muted))] text-[var(--color-danger)] flex items-center justify-center mx-auto mb-4">
            <Icons.AlertCircle size={32} />
          </div>
          <h3 className="text-lg font-bold uv-text-primary mb-1">{t('cards_load_failed_title')}</h3>
          <p className="uv-text-muted text-sm mb-6">{t('cards_load_failed_desc')}</p>
          <Button onClick={() => { setLoading(true); void load(); }} size="lg" fullWidth variant="secondary">
            {t('error_retry')}
          </Button>
        </div>
      ) : !card ? (
        /* Empty state — no active card yet */
        <div className="uv-surface-1 rounded-3xl p-8 text-center uv-shadow-soft">
          <div className="w-16 h-16 rounded-2xl bg-[var(--color-primary-soft)] text-[var(--color-primary)] flex items-center justify-center mx-auto mb-4">
            <Icons.Card size={32} />
          </div>
          <h3 className="text-lg font-bold uv-text-primary mb-1">{t('card_no_cards_title')}</h3>
          <p className="uv-text-muted text-sm mb-6">{t('card_no_cards_desc')}</p>
          {error && <p className="text-[var(--color-danger)] text-sm mb-4">{error}</p>}
          <Button onClick={handleCreate} size="lg" fullWidth disabled={busy}>
            {busy ? t('processing') : t('card_create')}
          </Button>
        </div>
      ) : (
        <>
          {/* El fallo de congelar, cambiar limites o cancelar se escribia en
              `error`, pero el unico sitio que lo pintaba estaba dentro del
              estado vacio — la rama que NO se muestra cuando hay tarjeta. Es
              decir: justo las acciones que solo existen teniendo una tarjeta
              fallaban en silencio. */}
          {error && (
            <p className="text-[var(--color-danger)] text-sm text-center" aria-live="polite">
              {error}
            </p>
          )}

          {/* Card Visual */}
          <div className="relative h-56 w-full max-w-md mx-auto perspective-1000">
            <div className={`relative w-full h-full rounded-3xl p-6 text-white uv-shadow-floating overflow-hidden uv-gradient-brand ${frozen ? 'grayscale opacity-90' : ''}`}>
              <div
                className="absolute -right-12 -top-12 w-48 h-48 rounded-full opacity-30 pointer-events-none"
                style={{ background: 'radial-gradient(closest-side, rgba(255,255,255,0.6), transparent)' }}
              />
              {frozen && (
                <div className="absolute inset-0 bg-[var(--color-navy-950)]/80 backdrop-blur-sm z-20 flex flex-col items-center justify-center rounded-3xl">
                  <Icons.Lock size={48} className="text-white/60 mb-2" />
                  <span className="font-bold text-white/85 tracking-widest">{t('card_frozen_label')}</span>
                </div>
              )}

              <div className="relative flex justify-between items-start mb-8 z-10">
                <span className="font-bold text-lg tracking-wide opacity-90">KiramoPay</span>
                <Icons.SignalHigh size={24} className="opacity-70" />
              </div>

              <div className="relative mb-8 z-10">
                <div className="w-12 h-8 rounded-md mb-2 bg-gradient-to-br from-amber-200 to-yellow-400 uv-shadow-soft" />
                <div className="font-mono text-2xl tracking-widest drop-shadow-md tabular-nums">
                  •••• •••• •••• {card.last4}
                </div>
              </div>

              <div className="relative flex justify-between items-end z-10">
                <div>
                  <div className="text-[10px] opacity-70 uppercase tracking-widest mb-1">{t('card_holder')}</div>
                  <div className="font-medium tracking-wide uppercase">{card.cardholderName}</div>
                </div>
                <div className="text-2xl font-bold italic opacity-85">{card.brand === 'mastercard' ? 'MC' : 'VISA'}</div>
              </div>
            </div>
          </div>

          {/* Controls */}
          <div>
            <h3 className="text-base font-bold uv-text-primary mb-3 tracking-tight">{t('card_controls')}</h3>
            <div className="uv-surface-1 rounded-2xl uv-shadow-soft divide-y divide-[var(--color-border)] dark:divide-[var(--color-border-dark)] overflow-hidden">
              <button
                onClick={handleFreeze}
                disabled={busy}
                className="w-full flex items-center px-4 py-4 hover:bg-[var(--color-surface-2)] dark:hover:bg-[var(--color-surface-2-dark)] transition-colors active:scale-[0.997] disabled:opacity-60"
              >
                <div className="w-10 h-10 rounded-full bg-[var(--color-primary-soft)] text-[var(--color-primary)] flex items-center justify-center mr-4 shrink-0">
                  <Icons.Freeze size={20} />
                </div>
                <div className="flex-1 text-left min-w-0">
                  <div className="font-semibold uv-text-primary text-sm">{frozen ? t('card_unfreeze') : t('card_freeze')}</div>
                  <div className="text-xs uv-text-muted mt-0.5">{t('card_freeze_desc')}</div>
                </div>
                <div className={`w-12 h-7 rounded-full p-1 transition-colors shrink-0 ${frozen ? 'bg-[var(--color-primary)]' : 'bg-[var(--color-border-strong)] dark:bg-[var(--color-border-dark)]'}`}>
                  <div className={`w-5 h-5 bg-white rounded-full uv-shadow-soft transition-transform ${frozen ? 'translate-x-5' : ''}`} />
                </div>
              </button>

              <button
                onClick={openLimits}
                className="w-full flex items-center px-4 py-4 hover:bg-[var(--color-surface-2)] dark:hover:bg-[var(--color-surface-2-dark)] transition-colors active:scale-[0.997]"
              >
                <div className="w-10 h-10 rounded-full bg-[var(--color-accent-soft)] text-[var(--color-accent)] flex items-center justify-center mr-4 shrink-0">
                  <Icons.Sliders size={20} />
                </div>
                <div className="flex-1 text-left min-w-0">
                  <div className="font-semibold uv-text-primary text-sm">{t('card_limits_title')}</div>
                  <div className="text-xs uv-text-muted mt-0.5">{t('card_limits_desc')}</div>
                </div>
                <Icons.ChevronRight size={20} className="uv-text-muted shrink-0" />
              </button>

              <button
                onClick={() => setShowCancel(true)}
                className="w-full flex items-center px-4 py-4 hover:bg-[var(--color-surface-2)] dark:hover:bg-[var(--color-surface-2-dark)] transition-colors active:scale-[0.997]"
              >
                <div className="w-10 h-10 rounded-full bg-[var(--color-danger-soft)] text-[var(--color-danger)] flex items-center justify-center mr-4 shrink-0">
                  <Icons.XCircle size={20} />
                </div>
                <div className="flex-1 text-left min-w-0">
                  <div className="font-semibold uv-text-primary text-sm">{t('card_cancel')}</div>
                </div>
                <Icons.ChevronRight size={20} className="uv-text-muted shrink-0" />
              </button>
            </div>
          </div>

          {/* Spend vs limit summary */}
          <div className="uv-surface-1 rounded-2xl p-4 uv-shadow-soft space-y-2">
            <div className="flex justify-between text-sm">
              <span className="uv-text-muted">{t('daily_limit')}</span>
              <span className="font-semibold uv-text-primary tabular-nums">{formatCRC(card.dailySpent)} / {formatCRC(card.dailyLimit)}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="uv-text-muted">{t('card_atm_limit')}</span>
              <span className="font-semibold uv-text-primary tabular-nums">{formatCRC(card.atmLimit)}</span>
            </div>
          </div>
        </>
      )}

      {/* Limits Bottom Sheet */}
      <BottomSheet isOpen={showLimits} onClose={() => setShowLimits(false)} title={t('card_limits_title')}>
        <div className="space-y-8 p-2">
          <div>
            <div className="flex justify-between mb-2">
              <label className="font-semibold uv-text-primary">{t('daily_limit')}</label>
              <span className="text-[var(--color-primary)] font-bold tabular-nums">{formatCRC(tempDaily)}</span>
            </div>
            <input
              type="range" min={0} max={1000000} step={10000}
              value={tempDaily}
              onChange={(e) => setTempDaily(parseInt(e.target.value, 10))}
              className="w-full h-2 bg-[var(--color-surface-muted)] dark:bg-[var(--color-surface-muted-dark)] rounded-lg appearance-none cursor-pointer accent-[var(--color-primary)]"
            />
          </div>
          <div>
            <div className="flex justify-between mb-2">
              <label className="font-semibold uv-text-primary">{t('card_atm_limit')}</label>
              <span className="text-[var(--color-primary)] font-bold tabular-nums">{formatCRC(tempAtm)}</span>
            </div>
            <input
              type="range" min={0} max={200000} step={5000}
              value={tempAtm}
              onChange={(e) => setTempAtm(parseInt(e.target.value, 10))}
              className="w-full h-2 bg-[var(--color-surface-muted)] dark:bg-[var(--color-surface-muted-dark)] rounded-lg appearance-none cursor-pointer accent-[var(--color-primary)]"
            />
          </div>
          <Button onClick={saveLimits} size="lg" fullWidth disabled={busy}>
            {busy ? t('processing') : t('save')}
          </Button>
        </div>
      </BottomSheet>

      {/* Cancel confirmation */}
      <BottomSheet isOpen={showCancel} onClose={() => setShowCancel(false)} title={t('card_cancel')}>
        <div className="space-y-4 py-2">
          <p className="uv-text-secondary text-sm">{t('card_cancel_confirm')}</p>
          <div className="flex gap-2.5">
            <button
              onClick={() => setShowCancel(false)}
              className="flex-1 bg-[var(--color-surface-muted)] dark:bg-[var(--color-surface-muted-dark)] uv-text-primary py-4 rounded-xl font-bold active:scale-[0.98] transition-transform"
            >
              {t('close')}
            </button>
            <button
              onClick={confirmCancel}
              disabled={busy}
              className="flex-1 bg-[var(--color-danger)] text-white py-4 rounded-xl font-bold active:scale-[0.98] transition-transform disabled:opacity-60"
            >
              {busy ? t('processing') : t('card_cancel')}
            </button>
          </div>
        </div>
      </BottomSheet>

      {/* One-time reveal of full card details after creation */}
      <BottomSheet isOpen={showReveal} onClose={() => { setShowReveal(false); setRevealed(null); }} title={t('card_created_title')}>
        <div className="space-y-4 py-2">
          <p className="uv-text-muted text-sm">{t('card_created_desc')}</p>
          {revealed && (
            <div className="uv-surface-2 rounded-2xl p-4 space-y-3">
              <div>
                <div className="text-xs uv-text-muted mb-1">{t('card_number_label')}</div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-lg tracking-wider uv-text-primary tabular-nums">{groupPan(revealed.cardNumber)}</span>
                  <button onClick={copyNumber} aria-label={t('copy')} className="uv-text-secondary shrink-0">
                    <Icons.Copy size={18} />
                  </button>
                </div>
              </div>
              <div className="flex gap-6">
                <div>
                  <div className="text-xs uv-text-muted mb-1">{t('card_expiry_label')}</div>
                  <div className="font-mono uv-text-primary tabular-nums">
                    {String(revealed.expiryMonth).padStart(2, '0')}/{String(revealed.expiryYear).slice(-2)}
                  </div>
                </div>
                <div>
                  <div className="text-xs uv-text-muted mb-1">{t('card_cvv_label')}</div>
                  <div className="font-mono uv-text-primary tabular-nums">{revealed.cvv || '•••'}</div>
                </div>
              </div>
            </div>
          )}
          {copied && <p className="text-[var(--color-success)] text-sm text-center">{t('copied_to_clipboard')}</p>}
          <Button onClick={() => { setShowReveal(false); setRevealed(null); }} size="lg" fullWidth>
            {t('close')}
          </Button>
        </div>
      </BottomSheet>
    </div>
  );
};
