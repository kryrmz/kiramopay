import React, { useState } from 'react';
import { Icons } from '../../components/Icons';
import { Button } from '../../components/ui/Button';
import { useAuthStore } from '@/stores/auth.store';
import { useLanguage } from '../../i18n/LanguageContext';
import { getApiLayer } from '@/api';
import { normalizarCodigoInvitacion, clearReferralCode } from '@/utils/referralCode';
import { esNombreDeUsuarioValido } from '@/utils/identificador';

interface RegisterViewProps {
  onComplete: () => void;
  onBack: () => void;
  /** Código de invitación que trajo el enlace (?ref=); prellena el campo. */
  referralCode?: string;
}

type Step = 'phone' | 'otp' | 'cedula' | 'name' | 'usuario' | 'password';

// El orden de los pasos, en UN solo lugar. Estaba escrito dos veces a mano —en
// la barra de progreso y en la flecha de atras— y al agregar el paso del nombre
// de usuario ninguna de las dos copias se actualizo: la barra se quedaba en 0%
// (indexOf devolvia -1) y la flecha no encontraba el paso actual, asi que no
// hacia nada. Una lista, dos lectores.
export const ORDEN_DE_PASOS: Step[] = ['phone', 'otp', 'cedula', 'name', 'usuario', 'password'];

const getPasswordStrength = (pwd: string): { labelKey: string; color: string; textColor: string; width: string } => {
  if (pwd.length === 0) return { labelKey: '', color: '', textColor: '', width: '0%' };
  let score = 0;
  if (pwd.length >= 8) score++;
  if (pwd.length >= 12) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[a-z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;

  if (score <= 2) return { labelKey: 'password_weak', color: 'bg-red-500', textColor: 'text-red-400', width: '25%' };
  if (score <= 3) return { labelKey: 'password_medium', color: 'bg-yellow-500', textColor: 'text-yellow-400', width: '50%' };
  if (score <= 4) return { labelKey: 'password_good', color: 'bg-blue-500', textColor: 'text-blue-400', width: '75%' };
  return { labelKey: 'password_strong', color: 'bg-green-500', textColor: 'text-green-400', width: '100%' };
};

// Mirrors the backend policy (validator.ValidatePassword): >=8 chars with an
// uppercase, a lowercase, a digit and a special character. The frontend used to
// only require length >= 8, so ordinary passwords passed the UI and were then
// rejected by the server with a raw English 400 ("password must include ...") —
// which surfaced to users as a generic "error al crear la cuenta".
const isPasswordComplex = (pwd: string): boolean =>
  pwd.length >= 8 &&
  /[A-Z]/.test(pwd) &&
  /[a-z]/.test(pwd) &&
  /[0-9]/.test(pwd) &&
  /[^A-Za-z0-9]/.test(pwd);

// Contrato de POST /auth/register: cada codigo tiene su mensaje propio y todo
// lo demas cae al generico. El texto del servidor NUNCA se muestra: llegaba
// crudo al usuario, incluido el detalle interno de la base de datos en un 409.
const CLAVE_POR_CODIGO_REGISTRO: Record<string, string> = {
  REFERRAL_CODE_INVALID: 'reg_referral_invalid',
  USER_EXISTS: 'reg_err_user_exists',
  PHONE_NOT_VERIFIED: 'reg_err_phone_not_verified',
  CEDULA_INVALID: 'reg_err_cedula_invalid',
  // El nombre de usuario tomado SI se dice, a diferencia de la cedula o el
  // telefono, que se colapsan en USER_EXISTS para no confirmar que ese dato
  // esta registrado: un nombre de usuario es publico por naturaleza y quien se
  // registra necesita saber que tiene que elegir otro.
  USERNAME_TAKEN: 'reg_usuario_tomado',
  USERNAME_INVALID: 'reg_usuario_invalido',
};

const claveErrorRegistro = (code?: string): string =>
  (code && CLAVE_POR_CODIGO_REGISTRO[code]) || 'reg_err_generic';

export const RegisterView: React.FC<RegisterViewProps> = ({ onComplete, onBack, referralCode }) => {
  const { t } = useLanguage();
  const [step, setStep] = useState<Step>('phone');
  // Editable: el invitado puede corregirlo o borrarlo si el backend lo rechaza.
  const [codigoInvitacion, setCodigoInvitacion] = useState(referralCode ?? '');
  const [phone, setPhone] = useState('');
  // El código de verificación viaja al correo (SES es el canal real hoy); el
  // teléfono queda como la identidad de la cuenta.
  const [email, setEmail] = useState('');
  const [verificationToken, setVerificationToken] = useState('');
  // Eco del código cuando el backend corre en desarrollo (sin buzón real).
  const [devCode, setDevCode] = useState('');
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [cedula, setCedula] = useState({ type: 'nacional', part1: '', part2: '', part3: '' });
  // Nombre de usuario: es con lo que se va a entrar. Se propone uno a partir
  // del nombre para que nadie tenga que inventarlo, pero se puede cambiar.
  const [usuario, setUsuario] = useState('');
  const [name, setName] = useState({ firstName: '', lastName: '' });
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const register = useAuthStore((s) => s.register);

  // Los pasos de teléfono y código hablan con el backend DE VERDAD. Antes esto
  // era un setTimeout decorativo: nunca se pedía el código, la pantalla de OTP
  // aceptaba cualquier cosa y la cuenta nacía sin verificar y sin correo.
  const handleNext = async () => {
    setError('');
    switch (step) {
      case 'phone': {
        setIsLoading(true);
        const res = await getApiLayer().auth.sendRegistrationOtp(`+506${phone}`, email.trim());
        setIsLoading(false);
        if (!res.success) {
          setError(res.error?.message || t('reg_otp_send_failed'));
          return;
        }
        setDevCode(res.data?.devCode || '');
        setOtp(['', '', '', '', '', '']);
        setStep('otp');
        break;
      }
      case 'otp': {
        setIsLoading(true);
        const res = await getApiLayer().auth.verifyRegistrationOtp(`+506${phone}`, otp.join(''));
        setIsLoading(false);
        if (!res.success || !res.data) {
          setError(t('reg_otp_invalid'));
          return;
        }
        setVerificationToken(res.data.verificationToken);
        setStep('cedula');
        break;
      }
      case 'cedula':
        setStep('name');
        break;
      case 'name':
        // Propuesta a partir del nombre, solo si el usuario no escribio uno.
        // Se limpia a lo que el formato admite y se recorta al maximo.
        if (!usuario) {
          const propuesta = name.firstName
            .toLowerCase()
            .normalize('NFD')
            .replace(/[̀-ͯ]/g, '')
            .replace(/[^a-z0-9._-]/g, '')
            .slice(0, 20);
          if (esNombreDeUsuarioValido(propuesta)) setUsuario(propuesta);
        }
        setStep('usuario');
        break;
      case 'usuario':
        setStep('password');
        break;
    }
  };

  const handleRegister = async () => {
    if (password !== confirmPassword) {
      setError(t('passwords_dont_match'));
      return;
    }
    if (!isPasswordComplex(password)) {
      setError(t('password_requirements'));
      return;
    }

    // Un código a medias no se manda "vacío" en silencio: el invitado lo
    // corrige o lo borra, igual que cuando el backend no lo encuentra.
    const codigo = normalizarCodigoInvitacion(codigoInvitacion);
    if (codigoInvitacion.trim() && !codigo) {
      setError(t('reg_referral_invalid'));
      return;
    }

    setIsLoading(true);
    setError('');

    const fullCedula = `${cedula.part1}${cedula.part2}${cedula.part3}`;
    const result = await register({
      cedula: fullCedula,
      username: usuario,
      phone: `+506${phone}`,
      firstName: name.firstName,
      lastName: name.lastName,
      password,
      // El correo queda en la cuenta (sin él, ni la recuperación de contraseña
      // puede funcionar) y el token prueba que el código llegó a ese correo.
      email: email.trim(),
      verificationToken,
      // Solo viaja si existe: sin código, el payload queda igual que siempre.
      ...(codigo ? { referralCode: codigo } : {}),
    });

    setIsLoading(false);

    if (result.success) {
      clearReferralCode();
      onComplete();
      return;
    }
    // Si lo que fallo es el nombre de usuario, se vuelve a ESE paso: dejar al
    // usuario en la pantalla de la contrasena con un error sobre otro campo lo
    // obligaria a rehacer el asistente para corregir una letra.
    if (result.code === 'USERNAME_TAKEN' || result.code === 'USERNAME_INVALID') {
      setStep('usuario');
    }
    setError(t(claveErrorRegistro(result.code)));
  };

  const handleOtpChange = (index: number, value: string) => {
    if (value.length <= 1) {
      const newOtp = [...otp];
      newOtp[index] = value;
      setOtp(newOtp);
      if (value && index < 5) {
        document.getElementById(`reg-otp-${index + 1}`)?.focus();
      }
    }
  };

  const strength = getPasswordStrength(password);

  const renderStep = () => {
    switch (step) {
      case 'phone':
        return (
          <div className="animate-in fade-in slide-in-from-right duration-300">
            <div className="w-16 h-16 uv-gradient-brand rounded-2xl flex items-center justify-center mb-6">
              <Icons.Phone size={32} className="text-white" />
            </div>
            <h1 className="text-2xl font-black text-white mb-2">
              {t('reg_phone_title')}
            </h1>
            <p className="text-[var(--color-text-muted-dark)] mb-6">
              {t('reg_phone_desc')}
            </p>

            <div className="flex gap-3 mb-4">
              <div className="flex items-center gap-2 bg-[var(--color-surface-2-dark)] px-4 py-4 rounded-xl border border-[var(--color-border-dark)]">
                <span className="text-xl">🇨🇷</span>
                <span className="text-white font-medium">+506</span>
              </div>
              <input
                type="tel"
                value={phone}
                onChange={(e) => setPhone(e.target.value.replace(/\D/g, '').slice(0, 8))}
                placeholder="8888-0000"
                className="flex-1 bg-[var(--color-surface-2-dark)] px-4 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium placeholder:text-[var(--color-text-muted-dark)] outline-none focus:border-[var(--color-primary)] transition-colors"
                autoFocus
              />
            </div>

            {/* El código de verificación viaja al correo: pedirlo aquí es lo
                que permite completar el registro (no hay proveedor de SMS). */}
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={t('reg_email_label')}
              className="w-full bg-[var(--color-surface-2-dark)] px-4 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium placeholder:text-[var(--color-text-muted-dark)] outline-none focus:border-[var(--color-primary)] transition-colors mb-2"
            />
            <p className="text-sm text-[var(--color-text-muted-dark)] mb-6">
              {t('reg_email_hint')}
            </p>

            {/* Vino por un enlace de invitación: se lo decimos desde el primer
                paso para que sepa que el código ya está puesto. */}
            {referralCode && (
              <p className="flex items-center gap-2 text-sm text-[var(--color-text-muted-dark)] mb-6">
                <Icons.Gift size={16} className="text-[var(--color-accent)] shrink-0" />
                <span>{t('reg_referral_from').replace('{code}', referralCode)}</span>
              </p>
            )}

            {error && <p className="text-red-400 text-sm mb-4" aria-live="polite">{error}</p>}

            <Button
              variant="primary"
              size="lg"
              fullWidth
              onClick={handleNext}
              loading={isLoading}
              disabled={phone.length < 8 || !/^\S+@\S+\.\S+$/.test(email.trim())}
            >
              {t('continue')}
            </Button>
          </div>
        );

      case 'otp':
        return (
          <div className="animate-in fade-in slide-in-from-right duration-300">
            <div className="w-16 h-16 uv-gradient-brand rounded-2xl flex items-center justify-center mb-6">
              <Icons.Shield size={32} className="text-white" />
            </div>
            <h1 className="text-2xl font-black text-white mb-2">
              {t('reg_verify_title')}
            </h1>
            <p className="text-[var(--color-text-muted-dark)] mb-6">
              {t('reg_code_sent_to')} {email.trim()}
            </p>

            {/* Solo con el backend en desarrollo: eco del código para probar
                sin buzón. En producción dev_code no existe. */}
            {devCode && import.meta.env.DEV && (
              <p className="text-xs text-[var(--color-text-muted-dark)] mb-4 text-center">
                dev: {devCode}
              </p>
            )}

            {error && <p className="text-red-400 text-sm mb-4 text-center" aria-live="polite">{error}</p>}

            <div className="flex gap-2 justify-center mb-6">
              {otp.map((digit, index) => (
                <input
                  key={index}
                  id={`reg-otp-${index}`}
                  type="text"
                  inputMode="numeric"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleOtpChange(index, e.target.value)}
                  className="w-11 h-14 bg-[var(--color-surface-2-dark)] border-2 border-[var(--color-border-dark)] rounded-xl text-center text-xl font-bold text-white outline-none focus:border-[var(--color-primary)]"
                />
              ))}
            </div>

            <Button
              variant="primary"
              size="lg"
              fullWidth
              onClick={handleNext}
              loading={isLoading}
              disabled={otp.some(d => !d)}
            >
              {t('verify')}
            </Button>
          </div>
        );

      case 'cedula':
        return (
          <div className="animate-in fade-in slide-in-from-right duration-300">
            <div className="w-16 h-16 uv-gradient-brand rounded-2xl flex items-center justify-center mb-6">
              <Icons.User size={32} className="text-white" />
            </div>
            <h1 className="text-2xl font-black text-white mb-2">
              {t('reg_cedula_title')}
            </h1>
            <p className="text-[var(--color-text-muted-dark)] mb-6">
              {t('reg_cedula_desc')}
            </p>

            {/* Tipo de cedula */}
            <div className="flex gap-2 mb-4">
              {[
                { id: 'nacional', label: t('reg_cedula_nacional') },
                { id: 'residente', label: t('reg_cedula_residente') },
                { id: 'dimex', label: t('reg_cedula_dimex') },
              ].map((type) => (
                <button
                  key={type.id}
                  onClick={() => setCedula({ ...cedula, type: type.id })}
                  className={`flex-1 py-2 rounded-lg text-sm font-bold transition-all ${
                    cedula.type === type.id
                      ? 'bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white'
                      : 'bg-[var(--color-surface-2-dark)] text-[var(--color-text-muted-dark)]'
                  }`}
                >
                  {type.label}
                </button>
              ))}
            </div>

            {/* Cedula input. min-w-0 y padding contenido: sin eso, la suma de
                anchos fijos + px-4 desbordaba en pantallas angostas y corria
                TODA la pagina hacia un lado (la barra de progreso se veia
                "desbalanceada" — era el scroll horizontal de la fila). */}
            <div className="flex gap-2 mb-6">
              <input
                type="text"
                inputMode="numeric"
                value={cedula.part1}
                onChange={(e) => setCedula({ ...cedula, part1: e.target.value.replace(/\D/g, '').slice(0, 1) })}
                placeholder="1"
                className="w-12 shrink-0 bg-[var(--color-surface-2-dark)] px-1 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium text-center outline-none focus:border-[var(--color-primary)]"
              />
              <span className="text-[var(--color-text-muted-dark)] self-center text-2xl">-</span>
              <input
                type="text"
                inputMode="numeric"
                value={cedula.part2}
                onChange={(e) => setCedula({ ...cedula, part2: e.target.value.replace(/\D/g, '').slice(0, 4) })}
                placeholder="1234"
                className="flex-1 min-w-0 bg-[var(--color-surface-2-dark)] px-2 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium text-center outline-none focus:border-[var(--color-primary)]"
              />
              <span className="text-[var(--color-text-muted-dark)] self-center text-2xl">-</span>
              <input
                type="text"
                inputMode="numeric"
                value={cedula.part3}
                onChange={(e) => setCedula({ ...cedula, part3: e.target.value.replace(/\D/g, '').slice(0, 4) })}
                placeholder="5678"
                className="flex-1 min-w-0 bg-[var(--color-surface-2-dark)] px-2 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium text-center outline-none focus:border-[var(--color-primary)]"
              />
            </div>

            <Button
              variant="primary"
              size="lg"
              fullWidth
              onClick={handleNext}
              loading={isLoading}
              disabled={!cedula.part1 || cedula.part2.length < 4 || cedula.part3.length < 4}
            >
              {t('continue')}
            </Button>
          </div>
        );

      case 'name':
        return (
          <div className="animate-in fade-in slide-in-from-right duration-300">
            <div className="w-16 h-16 uv-gradient-brand rounded-2xl flex items-center justify-center mb-6">
              <Icons.Edit size={32} className="text-white" />
            </div>
            <h1 className="text-2xl font-black text-white mb-2">
              {t('reg_name_title')}
            </h1>
            <p className="text-[var(--color-text-muted-dark)] mb-6">
              {t('reg_name_desc')}
            </p>

            <div className="space-y-4 mb-6">
              <input
                type="text"
                value={name.firstName}
                onChange={(e) => setName({ ...name, firstName: e.target.value })}
                placeholder={t('first_name')}
                className="w-full bg-[var(--color-surface-2-dark)] px-4 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium placeholder:text-[var(--color-text-muted-dark)] outline-none focus:border-[var(--color-primary)]"
                autoFocus
              />
              <input
                type="text"
                value={name.lastName}
                onChange={(e) => setName({ ...name, lastName: e.target.value })}
                placeholder={t('last_name')}
                className="w-full bg-[var(--color-surface-2-dark)] px-4 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium placeholder:text-[var(--color-text-muted-dark)] outline-none focus:border-[var(--color-primary)]"
              />
            </div>

            <Button
              variant="primary"
              size="lg"
              fullWidth
              onClick={handleNext}
              loading={isLoading}
              disabled={!name.firstName || !name.lastName}
            >
              {t('continue')}
            </Button>
          </div>
        );

      case 'usuario': {
        const limpio = usuario.trim().toLowerCase();
        const valido = esNombreDeUsuarioValido(limpio);
        return (
          <div className="animate-in fade-in slide-in-from-right duration-300">
            <div className="w-16 h-16 uv-gradient-brand rounded-2xl flex items-center justify-center mb-6">
              <Icons.User size={32} className="text-white" />
            </div>
            <h1 className="text-2xl font-black text-white mb-2">{t('reg_usuario_title')}</h1>
            <p className="text-[var(--color-text-muted-dark)] mb-6">{t('reg_usuario_desc')}</p>

            <div className="mb-2">
              <input
                type="text"
                inputMode="text"
                autoCapitalize="none"
                autoCorrect="off"
                autoComplete="username"
                value={usuario}
                onChange={(e) => {
                  // Se normaliza mientras se escribe: asi lo que se ve es
                  // exactamente lo que se va a guardar, sin sorpresas al enviar.
                  setUsuario(e.target.value.toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 20));
                  setError('');
                }}
                placeholder={t('reg_usuario_placeholder')}
                className="w-full bg-[var(--color-surface-2-dark)] px-4 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium placeholder:text-[var(--color-text-muted-dark)] outline-none focus:border-[var(--color-primary)]"
                autoFocus
              />
            </div>
            {/* La regla se dice ANTES de fallar, no despues: el formato lo
                comparte el servidor y un rechazo al final del asistente seria
                el peor momento para enterarse. */}
            <p className={`text-sm mb-2 ${limpio && !valido ? 'text-[var(--color-danger)]' : 'text-[var(--color-text-muted-dark)]'}`}>
              {t('reg_usuario_regla')}
            </p>
            {/* El rebote desde el ultimo paso (nombre ya tomado, o rechazado
                por el servidor) devuelve a esta pantalla. Sin esto, el usuario
                volvia aqui sin ninguna explicacion de por que. */}
            {error && (
              <p className="text-[var(--color-danger)] text-sm mb-6" aria-live="polite">
                {error}
              </p>
            )}
            {!error && <div className="mb-6" />}

            <Button
              variant="primary"
              size="lg"
              fullWidth
              onClick={handleNext}
              loading={isLoading}
              disabled={!valido}
            >
              {t('continue')}
            </Button>
          </div>
        );
      }

      case 'password':
        return (
          <div className="animate-in fade-in slide-in-from-right duration-300">
            <div className="w-16 h-16 uv-gradient-brand rounded-2xl flex items-center justify-center mb-6">
              <Icons.Lock size={32} className="text-white" />
            </div>
            <h1 className="text-2xl font-black text-white mb-2">
              {t('reg_password_title')}
            </h1>
            <p className="text-[var(--color-text-muted-dark)] mb-6">
              {t('reg_password_desc')}
            </p>

            <div className="space-y-4 mb-6">
              <div>
                <label className="text-sm text-[var(--color-text-muted-dark)] mb-2 block">{t('password')}</label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      setError('');
                    }}
                    placeholder={t('password')}
                    className="w-full bg-[var(--color-surface-2-dark)] px-4 pr-12 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-medium placeholder:text-[var(--color-text-muted-dark)] outline-none focus:border-[var(--color-primary)]"
                    autoFocus
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-[var(--color-text-muted-dark)] hover:text-white"
                  >
                    {showPassword ? <Icons.EyeOff size={20} /> : <Icons.Eye size={20} />}
                  </button>
                </div>

                {/* Password strength indicator */}
                {password.length > 0 && (
                  <div className="mt-2">
                    <div className="h-1.5 bg-[var(--color-surface-3-dark)] rounded-full overflow-hidden">
                      <div
                        className={`h-full ${strength.color} transition-all duration-300`}
                        style={{ width: strength.width }}
                      />
                    </div>
                    <p className={`text-xs mt-1 ${strength.textColor}`}>
                      {t(strength.labelKey)}
                    </p>
                  </div>
                )}
                {/* Show the exact policy so users don't hit the backend 400 */}
                {password.length > 0 && !isPasswordComplex(password) && (
                  <p className="text-xs mt-1.5 text-[var(--color-text-muted-dark)]">
                    {t('password_requirements')}
                  </p>
                )}
              </div>

              <div>
                <label className="text-sm text-[var(--color-text-muted-dark)] mb-2 block">{t('confirm_password')}</label>
                <div className="relative">
                  <input
                    type={showConfirmPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => {
                      setConfirmPassword(e.target.value);
                      setError('');
                    }}
                    placeholder={t('confirm_password')}
                    className={`w-full bg-[var(--color-surface-2-dark)] px-4 pr-12 py-4 rounded-xl border text-white text-lg font-medium placeholder:text-[var(--color-text-muted-dark)] outline-none transition-colors ${
                      confirmPassword && password !== confirmPassword ? 'border-[var(--color-danger)]' : 'border-[var(--color-border-dark)] focus:border-[var(--color-primary)]'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-[var(--color-text-muted-dark)] hover:text-white"
                  >
                    {showConfirmPassword ? <Icons.EyeOff size={20} /> : <Icons.Eye size={20} />}
                  </button>
                </div>
              </div>

              <div>
                <label htmlFor="reg-referral" className="text-sm text-[var(--color-text-muted-dark)] mb-2 block">
                  {t('reg_referral_label')}
                </label>
                {/* Solo el alfabeto del backend (^[A-Z0-9]{8}$): se pasa a
                    mayúsculas y se quitan espacios al teclear o pegar. */}
                <input
                  id="reg-referral"
                  type="text"
                  value={codigoInvitacion}
                  onChange={(e) => {
                    setCodigoInvitacion(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8));
                    setError('');
                  }}
                  placeholder={t('reg_referral_placeholder')}
                  autoCapitalize="characters"
                  autoCorrect="off"
                  spellCheck={false}
                  maxLength={8}
                  className="w-full bg-[var(--color-surface-2-dark)] px-4 py-4 rounded-xl border border-[var(--color-border-dark)] text-white text-lg font-mono tracking-widest placeholder:font-sans placeholder:tracking-normal placeholder:text-[var(--color-text-muted-dark)] outline-none focus:border-[var(--color-primary)] transition-colors"
                />
              </div>

              {confirmPassword && password !== confirmPassword && (
                <p className="text-[var(--color-danger)] text-sm">{t('passwords_dont_match')}</p>
              )}
              {error && (
                <p className="text-[var(--color-danger)] text-sm flex items-center gap-1" aria-live="polite">
                  <Icons.AlertCircle size={14} />
                  {error}
                </p>
              )}
            </div>

            <Button
              variant="primary"
              size="lg"
              fullWidth
              onClick={handleRegister}
              loading={isLoading}
              disabled={!isPasswordComplex(password) || password !== confirmPassword}
              rightIcon={<Icons.Check size={20} />}
            >
              {t('create_account')}
            </Button>
          </div>
        );
    }
  };

  const getProgress = () => {
    return ((ORDEN_DE_PASOS.indexOf(step) + 1) / ORDEN_DE_PASOS.length) * 100;
  };

  return (
    <div className="min-h-screen overflow-x-hidden bg-gradient-to-b from-[var(--color-background-dark)] to-[var(--color-surface-1-dark)] flex flex-col">
      {/* Header */}
      <div className="p-4 pt-6">
        <div className="flex items-center justify-between mb-4">
          <button
            onClick={step === 'phone' ? onBack : () => {
              const actual = ORDEN_DE_PASOS.indexOf(step);
              if (actual > 0) setStep(ORDEN_DE_PASOS[actual - 1]);
            }}
            className="p-2 -ml-2 text-[var(--color-text-muted-dark)] hover:text-white transition-colors"
          >
            <Icons.ChevronLeft size={24} />
          </button>
          <span className="text-[var(--color-text-muted-dark)] text-sm">{t('create_account')}</span>
          <div className="w-8" />
        </div>

        {/* Progress bar */}
        <div className="h-1 bg-[var(--color-surface-3-dark)] rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-primary to-accent transition-all duration-500"
            style={{ width: `${getProgress()}%` }}
          />
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 px-6 pt-8">
        {renderStep()}
      </div>

      {/* Security note */}
      <div className="p-6 pb-8">
        <div className="flex items-center gap-3 bg-[var(--color-surface-2-dark)]/50 p-4 rounded-xl">
          <Icons.Shield size={20} className="text-green-500" />
          <p className="text-[var(--color-text-muted-dark)] text-xs">
            {t('reg_security_note')}
          </p>
        </div>
      </div>
    </div>
  );
};
