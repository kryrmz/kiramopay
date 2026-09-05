package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kiramopay/backend/internal/audit"
	"github.com/kiramopay/backend/internal/messaging"
	"github.com/kiramopay/backend/internal/middleware"
	"github.com/kiramopay/backend/internal/user"
	"github.com/kiramopay/backend/internal/wallet"
	"github.com/kiramopay/backend/pkg/hash"
	"github.com/kiramopay/backend/pkg/identifier"
	jwtpkg "github.com/kiramopay/backend/pkg/jwt"
)

// ErrInvalidCredentials is the constant-time error returned for any failed
// login (wrong cedula, wrong password, locked, etc.) to prevent enumeration.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrInvalidOTP is returned when a registration OTP code is wrong or expired.
var ErrInvalidOTP = errors.New("invalid or expired verification code")

// ErrPhoneNotVerified is returned by Register when phone verification is
// required but no valid verification token was presented for the phone.
var ErrPhoneNotVerified = errors.New("phone number not verified")

// ErrCedulaNoUsableEnLogin se devuelve en Register cuando la cedula, aun
// siendo de largo valido, clasificaria como otro tipo en el login (p.ej. 11
// digitos con prefijo 506 = telefono) y por lo tanto nunca serviria para
// entrar.
var ErrCedulaNoUsableEnLogin = errors.New("cedula no utilizable para iniciar sesion")

// ErrReferralCodeInvalid se devuelve en Register cuando el codigo de
// invitacion no corresponde a ninguna cuenta activa. El invitado lo ve como
// 400 y puede corregirlo o borrarlo; ignorarlo en silencio dejaria a ambos
// lados esperando un bono que nunca llega.
var ErrReferralCodeInvalid = errors.New("referral code not found")

// ErrAccountBlocked se devuelve cuando la cuenta no esta activa (bloqueada
// por un administrador, suspendida o cerrada). En Login solo se llega aqui
// DESPUES de verificar la contrasena, para que el codigo distinto no sirva de
// oraculo de enumeracion. El motivo del bloqueo nunca sale al cliente.
var ErrAccountBlocked = errors.New("account blocked")

// ErrPasswordRequired: se intento entrar sin contrasena a una cuenta que si la
// pide. Tiene codigo propio para que la pantalla sepa que debe pedirla, en vez
// de mostrar "credenciales incorrectas" antes de que el usuario teclee nada.
//
// Este camino NO incrementa ningun contador de bloqueo: la pantalla sondea con
// la contrasena vacia para decidir si mostrar el campo, y si el sondeo contara
// como intento fallido, cinco pulsaciones de Enter bloquearian la cuenta 15
// minutos sin que nadie hubiera escrito una contrasena.
var ErrPasswordRequired = errors.New("password required")

// ErrUsernameInvalido: el nombre de usuario no calza el formato o esta en la
// lista de nombres reservados. Tiene codigo propio para que la pantalla lo diga
// junto al campo, en vez del 409 generico de "ya existe un usuario".
var ErrUsernameInvalido = errors.New("invalid username")

// ErrUsernameTomado: ese nombre de usuario ya es de alguien. A diferencia del
// choque de cedula o telefono, este SI se distingue del resto: un nombre de
// usuario es publico por naturaleza y decir que esta tomado no revela nada que
// no revele el propio hecho de que exista.
var ErrUsernameTomado = errors.New("username taken")

// ErrCuentaDeDemostracion se reexporta desde internal/user para que quien lee
// este paquete no tenga que saltar: una cuenta que abre sin contrasena no
// cambia su identidad ni sus credenciales.
var ErrCuentaDeDemostracion = user.ErrCuentaDeDemostracion

// ErrUserExists se devuelve en Register cuando la cedula, el telefono o el
// correo ya pertenecen a una cuenta. El handler lo traduce a 409 USER_EXISTS;
// que campo choco nunca sale al cliente.
var ErrUserExists = errors.New("user already registered")

// SanctionScreener gates onboarding against a sanction watchlist. Implemented
// by the kyc service; optional (nil disables the check).
type SanctionScreener interface {
	ScreenIsClear(ctx context.Context, fullName string) (bool, error)
}

// ReferralRewarder paga el bono de referido cuando un invitado completa el
// registro. Implementado por loyalty.Service; opcional (nil desactiva).
type ReferralRewarder interface {
	RewardReferral(ctx context.Context, referrerID, invitedUserID string) (bool, error)
}

type Service struct {
	authRepo         *Repository
	userRepo         *user.Repository
	walletRepo       *wallet.Repository
	jwt              *jwtpkg.Manager
	lockoutStore     middleware.LockoutStore
	auditLogger      *audit.Logger
	screener         SanctionScreener
	referrals        ReferralRewarder
	maxLoginAttempts int
	idleTimeout      time.Duration
	absoluteTimeout  time.Duration
	// requirePhoneVerification gates whether Register demands a valid phone
	// verification token. Off until an SMS provider can deliver the code.
	requirePhoneVerification bool
	// smsSender / emailSender deliver OTPs and the password-reset token. Nil when
	// no provider is configured, in which case the handler echoes the secret in
	// dev only. publicAppURL builds the reset link in the email.
	smsSender    messaging.SMSSender
	emailSender  messaging.EmailSender
	publicAppURL string
	// demoLoginEnabled habilita la entrada SIN CONTRASENA para las cuentas
	// marcadas con users.demo_login. Nace APAGADA y se enciende solo mientras
	// dure una demostracion: con ella encendida, cualquiera que sepa el nombre
	// de usuario de una cuenta marcada entra desde internet. El dueno pidio
	// esta funcion y asumio ese riesgo de forma explicita.
	demoLoginEnabled bool
}

// Options for service wiring.
type Options struct {
	LockoutStore middleware.LockoutStore
	AuditLogger  *audit.Logger
	Screener     SanctionScreener
	// Referrals acredita el bono al referidor al terminar un registro con
	// codigo de invitacion. Nil: la atribucion (referred_by) se guarda igual,
	// pero nadie cobra.
	Referrals        ReferralRewarder
	MaxLoginAttempts int
	// IdleTimeout ends a session after this much inactivity (no refresh).
	// AbsoluteTimeout caps the total session age from the original login.
	// Zero falls back to 30 minutes / 7 days respectively.
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	// RequirePhoneVerification makes Register reject signups without a valid
	// phone-verification token. Keep false until an SMS provider is wired
	// (otherwise nobody could obtain a code in production).
	RequirePhoneVerification bool
	// DemoLoginEnabled habilita la entrada SIN CONTRASENA para las cuentas
	// marcadas con users.demo_login. Se enciende con DEMO_LOGIN_ENABLED solo
	// mientras dure una demostracion.
	DemoLoginEnabled bool
	// SMSSender / EmailSender deliver registration OTPs and the password-reset
	// token. Nil disables delivery (dev-echo fallback). PublicAppURL is the
	// frontend origin used to build the reset link in the email.
	SMSSender    messaging.SMSSender
	EmailSender  messaging.EmailSender
	PublicAppURL string
}

func NewService(
	authRepo *Repository,
	userRepo *user.Repository,
	walletRepo *wallet.Repository,
	jwt *jwtpkg.Manager,
	opts *Options,
) *Service {
	if opts == nil {
		opts = &Options{}
	}
	if opts.MaxLoginAttempts <= 0 {
		opts.MaxLoginAttempts = 5
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 30 * time.Minute
	}
	if opts.AbsoluteTimeout <= 0 {
		opts.AbsoluteTimeout = 7 * 24 * time.Hour
	}
	return &Service{
		authRepo:                 authRepo,
		userRepo:                 userRepo,
		walletRepo:               walletRepo,
		jwt:                      jwt,
		lockoutStore:             opts.LockoutStore,
		auditLogger:              opts.AuditLogger,
		screener:                 opts.Screener,
		referrals:                opts.Referrals,
		maxLoginAttempts:         opts.MaxLoginAttempts,
		idleTimeout:              opts.IdleTimeout,
		absoluteTimeout:          opts.AbsoluteTimeout,
		requirePhoneVerification: opts.RequirePhoneVerification,
		smsSender:                opts.SMSSender,
		emailSender:              opts.EmailSender,
		publicAppURL:             opts.PublicAppURL,
		demoLoginEnabled:         opts.DemoLoginEnabled,
	}
}

// sessionWindowExceeded reports whether a session must end: either the presented
// refresh token was issued longer ago than the idle window (inactivity), or the
// family/login origin is older than the absolute window (max session age). A
// non-positive window disables that particular check.
func sessionWindowExceeded(now, tokenIssuedAt, familyOrigin time.Time, idle, absolute time.Duration) bool {
	if idle > 0 && now.Sub(tokenIssuedAt) > idle {
		return true
	}
	if absolute > 0 && now.Sub(familyOrigin) > absolute {
		return true
	}
	return false
}

type LoginRequest struct {
	// Identifier acepta cedula, correo o telefono en un solo campo; el tipo se
	// decide por forma (pkg/identifier). Cedula queda como alias legado: el APK
	// v2.0.x y clientes viejos siguen mandando {cedula, password} y funcionan.
	Identifier string `json:"identifier,omitempty"`
	Cedula     string `json:"cedula,omitempty"`
	Password   string `json:"password"`
}

// EffectiveIdentifier es el valor con el que se intenta entrar: identifier si
// vino, si no el alias legado cedula.
func (r *LoginRequest) EffectiveIdentifier() string {
	if r.Identifier != "" {
		return r.Identifier
	}
	return r.Cedula
}

type LoginContext struct {
	IPAddress string
	UserAgent string
}

type LoginResponse struct {
	User   *user.UserRecord  `json:"user"`
	Tokens *jwtpkg.TokenPair `json:"tokens"`
}

type RegisterRequest struct {
	Cedula    string `json:"cedula"`
	// Username es el nombre de usuario con el que se va a entrar. Opcional por
	// compatibilidad: los clientes viejos no lo mandan y siguen registrando
	// cuentas, que quedan sin nombre de usuario y entran por los otros tres
	// identificadores.
	Username  string `json:"username,omitempty"`
	Phone     string `json:"phone"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password"`
	Email     string `json:"email,omitempty"`
	// VerificationToken proves phone ownership (issued by VerifyRegistrationOTP).
	VerificationToken string `json:"verification_token,omitempty"`
	// ReferralCode es el codigo de invitacion de otro usuario (opcional). Se
	// normaliza (trim + mayusculas) y debe existir en una cuenta activa.
	ReferralCode string `json:"referral_code,omitempty"`
}

type SendRegistrationOTPRequest struct {
	Phone string `json:"phone"`
	// Email recibe el codigo de verificacion: es el canal que funciona hoy
	// (SES). El SMS queda de respaldo para cuando haya proveedor.
	Email string `json:"email"`
}

type VerifyRegistrationOTPRequest struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type ForgotPasswordRequest struct {
	// Identifier acepta lo mismo que el login: nombre de usuario, cedula,
	// correo o telefono. Cedula queda como alias legado, igual que en
	// LoginRequest: los APK viejos mandan {cedula} y tienen que seguir
	// recuperando su contrasena.
	Identifier string `json:"identifier,omitempty"`
	Cedula     string `json:"cedula,omitempty"`
}

// EffectiveIdentifier es el valor con el que se busca la cuenta: identifier si
// vino, si no el alias legado cedula.
func (r *ForgotPasswordRequest) EffectiveIdentifier() string {
	if r.Identifier != "" {
		return r.Identifier
	}
	return r.Cedula
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (s *Service) Login(ctx context.Context, req *LoginRequest, lc LoginContext) (*LoginResponse, error) {
	// Clasificacion defensiva aunque el handler ya haya validado: el servicio
	// jamas debe consultar la BD con un identificador sin canonicalizar.
	kind, canonical, cerr := identifier.Classify(req.EffectiveIdentifier())
	if cerr != nil {
		// Mismo presupuesto de CPU y misma respuesta que un usuario inexistente.
		hash.DummyVerify()
		if s.auditLogger != nil {
			s.auditLogger.LogLogin("", lc.IPAddress, lc.UserAgent, false, "")
		}
		return nil, ErrInvalidCredentials
	}

	// Contrasena vacia con la entrada sin contrasena APAGADA: la respuesta es la
	// misma exista o no la cuenta, asi que se contesta ANTES de consultar la
	// base. No es solo eficiencia: si se resolviera primero, el codigo de error
	// distinguiria una cuenta que existe (PASSWORD_REQUIRED) de una que no
	// (AUTH_FAILED), y eso convierte /auth/login en un listador de cuentas para
	// cualquiera, sin autenticar y sin gastar intentos. Todo el resto de esta
	// funcion esta construido para no filtrar eso (DummyVerify en tres sitios,
	// mensaje constante, una sola consulta por tipo para no dar oraculo de
	// tiempo); esta rama tiene que respetarlo igual.
	if req.Password == "" && !s.demoLoginEnabled {
		hash.DummyVerify()
		return nil, ErrPasswordRequired
	}

	u := s.resolveLoginUser(ctx, kind, canonical)
	if u == nil {
		// Con la bandera encendida y contrasena vacia, la respuesta tiene que
		// ser la MISMA que para una cuenta que existe pero pide contrasena.
		// Si aqui se devolviera credenciales invalidas, comparar los dos
		// codigos diria cuales identificadores tienen cuenta.
		if req.Password == "" {
			hash.DummyVerify()
			return nil, ErrPasswordRequired
		}
		// Anti-enumeration: spend the Argon2 budget anyway.
		hash.DummyVerify()
		s.incrementLockout(kind, canonical)
		if s.auditLogger != nil {
			s.auditLogger.LogLogin("", lc.IPAddress, lc.UserAgent, false, string(kind))
		}
		return nil, ErrInvalidCredentials
	}

	// ── Entrada sin contrasena ───────────────────────────────────────────
	// Pedido explicito del dueno para hacer demostraciones sin teclear una
	// contrasena delante de nadie. Exige DOS condiciones a la vez: que la
	// cuenta este marcada (users.demo_login) y que el servidor tenga la
	// bandera encendida (DEMO_LOGIN_ENABLED, que nace APAGADA). La bandera es
	// la palanca de la demostracion: se enciende, se demuestra, se apaga, sin
	// tocar ninguna fila.
	//
	// El riesgo esta asumido por el dueno y conviene que quede escrito: con la
	// bandera encendida, cualquiera que sepa el nombre de usuario entra desde
	// internet. Por eso queda en la auditoria con accion propia y riesgo alto.
	if req.Password == "" {
		if s.demoLoginEnabled && u.DemoLogin && u.Status == "active" {
			if s.auditLogger != nil {
				s.auditLogger.Log(audit.Event{
					UserID: u.ID, Action: "login_demo", ResourceType: "session",
					IPAddress: lc.IPAddress, UserAgent: lc.UserAgent,
					Details:   map[string]interface{}{"identifier_type": string(kind)},
					RiskLevel: "high",
				})
			}
			return s.emitirSesion(ctx, u, kind, canonical, lc)
		}
		// La cuenta no abre sin contrasena. Se responde con un codigo PROPIO y,
		// sobre todo, SIN tocar los contadores de bloqueo: la pantalla sondea
		// con la contrasena vacia para saber si tiene que pedirla, y si ese
		// sondeo contara como intento fallido, cinco pulsaciones de Enter
		// dejarian la cuenta bloqueada 15 minutos sin que nadie escribiera una
		// contrasena. Se quema el presupuesto de Argon2 igual, para que el
		// tiempo no distinga una cuenta que existe de una que no.
		hash.DummyVerify()
		return nil, ErrPasswordRequired
	}

	valid, err := hash.VerifyPin(req.Password, u.PasswordHash)
	if err != nil || !valid {
		s.incrementLockout(kind, canonical)
		// Segundo contador, por cuenta resuelta: sin el, una cuenta ganaria
		// maxLoginAttempts intentos POR CADA identificador (cedula, correo y
		// telefono llevan contadores distintos).
		s.incrementUserLockout(u.ID)
		if s.auditLogger != nil {
			s.auditLogger.LogLogin(u.ID, lc.IPAddress, lc.UserAgent, false, string(kind))
		}
		return nil, ErrInvalidCredentials
	}

	// Cuenta no activa: se rechaza con codigo propio SOLO con la contrasena ya
	// verificada (antes del hash revelaria que la cuenta existe). Cualquier
	// status distinto de 'active' recibe el mismo codigo; el detalle queda en
	// la auditoria, no en la respuesta.
	if u.Status != "active" {
		if s.auditLogger != nil {
			s.auditLogger.Log(audit.Event{
				UserID:       u.ID,
				Action:       "login_blocked",
				ResourceType: "session",
				IPAddress:    lc.IPAddress,
				UserAgent:    lc.UserAgent,
				Details:      map[string]interface{}{"status": u.Status},
				RiskLevel:    "medium",
			})
		}
		return nil, ErrAccountBlocked
	}

	return s.emitirSesion(ctx, u, kind, canonical, lc)
}

// emitirSesion es el tramo final del login, compartido por el camino con
// contrasena y por el de las cuentas de demostracion. Se extrajo para que los
// dos pasen EXACTAMENTE por los mismos controles finales y por el mismo
// registro de sesion: dos copias divergirian.
func (s *Service) emitirSesion(ctx context.Context, u *user.UserRecord, kind identifier.Kind, canonical string, lc LoginContext) (*LoginResponse, error) {
	// Block locked accounts AFTER hash verification too (defense in depth —
	// the middleware should have already blocked, but if it didn't, do not
	// issue tokens). Checks BOTH counters: per identifier and per account.
	if s.lockoutStore != nil {
		count := s.lockoutStore.GetLockout(identifier.LockoutKey(kind, canonical))
		if int(count) >= s.maxLoginAttempts {
			return nil, ErrInvalidCredentials
		}
		if s.isUserLockedOut(u.ID) {
			return nil, ErrInvalidCredentials
		}
	}

	tokens, err := s.jwt.GenerateTokenPair(u.ID)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	// Persist refresh token + session in one logical unit.
	if err := s.persistTokenRollout(ctx, u.ID, tokens, lc, ""); err != nil {
		return nil, fmt.Errorf("persist session: %w", err)
	}

	s.resetLockout(kind, canonical)
	s.resetUserLockout(u.ID)
	_ = s.userRepo.UpdateLastLogin(ctx, u.ID)
	if s.auditLogger != nil {
		s.auditLogger.LogLogin(u.ID, lc.IPAddress, lc.UserAgent, true, string(kind))
	}
	return &LoginResponse{User: u, Tokens: tokens}, nil
}

// resolveLoginUser hace EXACTAMENTE una consulta segun el tipo clasificado
// (nunca lookups en cascada: serian un oraculo de timing por tipo). Devuelve
// nil en cualquier fallo; el llamador quema el presupuesto de Argon2 igual.
func (s *Service) resolveLoginUser(ctx context.Context, kind identifier.Kind, canonical string) *user.UserRecord {
	var (
		u   *user.UserRecord
		err error
	)
	switch kind {
	case identifier.KindCedula:
		u, err = s.userRepo.FindByCedula(ctx, canonical)
	case identifier.KindPhone:
		u, err = s.userRepo.FindByPhone(ctx, canonical)
	case identifier.KindUsername:
		u, err = s.userRepo.FindByUsername(ctx, canonical)
	case identifier.KindEmail:
		u, err = s.userRepo.FindByEmail(ctx, canonical)
		// Un correo sin verificar NO autentica: es opcional y editable, y sin
		// este gate cualquiera podria apuntar un correo ajeno a su cuenta y
		// capturar los intentos de login del dueno real. Se trata como un miss
		// (mismo perfil de tiempo y misma respuesta).
		if err == nil && u != nil && !u.EmailVerified {
			u = nil
		}
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	return u
}

func (s *Service) Register(ctx context.Context, req *RegisterRequest, lc LoginContext) (*LoginResponse, error) {
	// Canonicalizar la cedula (solo digitos) ANTES de buscar y de guardar: el
	// HMAC de BD solo hace lower/trim, asi que "1-2345-6789" y "123456789"
	// serian dos hashes distintos y la cuenta quedaria imposible de encontrar
	// desde el login canonicalizado.
	req.Cedula = soloDigitos(req.Cedula)
	// La cedula debe clasificar COMO cedula para el login, o quedaria
	// registrada pero imposible de usar para entrar: p.ej. 11 digitos que
	// empiezan en 506 los toma el clasificador como telefono. ValidateCedula
	// (9-12 digitos) aceptaba esos casos; aqui se cierran contra la misma
	// regla que usa el login.
	if kind, _, cerr := identifier.Classify(req.Cedula); cerr != nil || kind != identifier.KindCedula {
		return nil, ErrCedulaNoUsableEnLogin
	}
	existing, _ := s.userRepo.FindByCedula(ctx, req.Cedula)
	if existing != nil {
		return nil, ErrUserExists
	}

	// Nombre de usuario. Es opcional: los clientes viejos no lo mandan y sus
	// registros siguen funcionando, con la cuenta entrando por los otros tres
	// identificadores. Cuando viene, se valida contra la MISMA regla que usa
	// el login (identifier.ValidUsername) para que no quede registrado un
	// nombre que despues no sirva para entrar — el mismo cuidado que
	// ErrCedulaNoUsableEnLogin tiene con la cedula.
	usernameCanonico := identifier.CanonicalizarUsername(req.Username)
	if usernameCanonico != "" {
		if !identifier.ValidUsername(usernameCanonico) {
			return nil, ErrUsernameInvalido
		}
		// Pre-chequeo para poder dar un error propio. La unicidad real la
		// sostiene el indice uq_users_username; una carrera entre dos registros
		// cae en el 23505 de mas abajo.
		if tomado, _ := s.userRepo.FindByUsername(ctx, usernameCanonico); tomado != nil {
			return nil, ErrUsernameTomado
		}
	}

	// Codigo de invitacion: se resuelve AQUI, antes de consumir el token de
	// verificacion (es de un solo uso) y antes de hashear. Un codigo que no
	// corresponde a una cuenta activa rechaza el registro entero, sin dejar
	// nada a medias. El registro del referidor jamas sale al cliente.
	var referrer *user.UserRecord
	if code := user.NormalizeReferralCode(req.ReferralCode); code != "" {
		found, rerr := s.userRepo.FindByReferralCode(ctx, code)
		switch {
		case errors.Is(rerr, pgx.ErrNoRows):
			return nil, ErrReferralCodeInvalid
		case rerr != nil:
			// Un fallo de BD no es un codigo invalido: mandaria al invitado a
			// "corregir" un codigo que quiza es correcto. Se propaga como error
			// interno.
			return nil, fmt.Errorf("lookup referral code: %w", rerr)
		case found == nil:
			return nil, ErrReferralCodeInvalid
		}
		referrer = found
	}

	// AML onboarding gate: refuse registration of sanctioned individuals.
	// Fail-open on screening *errors* (infra hiccup must not block all signups);
	// fail-closed on an actual hit.
	if s.screener != nil {
		clear, serr := s.screener.ScreenIsClear(ctx, req.FirstName+" "+req.LastName)
		if serr == nil && !clear {
			if s.auditLogger != nil {
				s.auditLogger.Log(audit.Event{
					Action:    "register_sanction_block",
					RiskLevel: "high",
					IPAddress: lc.IPAddress,
					UserAgent: lc.UserAgent,
				})
			}
			return nil, fmt.Errorf("registration cannot be completed")
		}
	}

	// Proof of phone ownership. A verification token is issued by
	// VerifyRegistrationOTP once the user enters the code sent to their phone.
	// When RequirePhoneVerification is on, a valid token for THIS phone is
	// mandatory; otherwise it is best-effort (records phone_verified when given).
	phoneVerified := false
	emailVerified := false
	if req.VerificationToken != "" {
		verifiedPhone, verifiedEmailHash, verr := s.authRepo.ConsumePhoneVerificationToken(ctx, req.VerificationToken)
		if verr != nil {
			return nil, fmt.Errorf("verify phone: %w", verr)
		}
		phoneVerified = verifiedPhone != "" && verifiedPhone == req.Phone
		// El codigo viajo al correo: probarlo prueba posesion de ese buzon.
		// Solo cuenta si es EL MISMO correo que se registra. Se compara por
		// HASH del correo canonico (el buzon nunca viaja en claro por Redis).
		emailVerified = phoneVerified && verifiedEmailHash != "" &&
			verifiedEmailHash == hashCorreoCanonico(req.Email)
	}
	if s.requirePhoneVerification && !phoneVerified {
		return nil, ErrPhoneNotVerified
	}

	pwHash, err := hash.HashPin(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	newUserID := uuid.New().String()
	// Atribucion: se escribe UNA vez, en el INSERT, y nunca se actualiza. La
	// guardia contra auto-referido es redundante (el invitado no existe cuando
	// se resuelve el codigo) pero gratis; la BD tiene su propio CHECK.
	var referredBy *string
	if referrer != nil && referrer.ID != newUserID {
		referredBy = &referrer.ID
	}
	// ReferralCode se deja vacio: lo genera userRepo.Create.
	newUser := &user.UserRecord{
		ID:            newUserID,
		Username:      usernameCanonico,
		Cedula:        req.Cedula,
		Phone:         req.Phone,
		PhoneVerified: phoneVerified,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Email:         req.Email,
		EmailVerified: emailVerified,
		PasswordHash:  pwHash,
		Status:        "active",
		KYCLevel:      0,
		ReferredBy:    referredBy,
	}
	if err := s.userRepo.Create(ctx, newUser); err != nil {
		// Telefono o correo ya registrados (la cedula se reviso arriba, pero
		// una carrera entre dos registros tambien cae aqui).
		if isUsersUniqueViolation(err) {
			return nil, ErrUserExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	if err := s.walletRepo.CreateForUser(ctx, newUser.ID); err != nil {
		return nil, fmt.Errorf("create wallet: %w", err)
	}

	// Bono al referidor, best-effort: el registro ya es valido (usuario y
	// wallet creados); si la acreditacion falla se loguea, no se deshace nada.
	// RewardReferral es idempotente por invitado (uq_loyalty_tx_referral).
	if referredBy != nil && s.referrals != nil {
		if _, rerr := s.referrals.RewardReferral(ctx, referrer.ID, newUser.ID); rerr != nil {
			slog.Warn("referral bonus not credited", "referrer", referrer.ID, "invited", newUser.ID, "err", rerr.Error())
		}
	}

	tokens, err := s.jwt.GenerateTokenPair(newUser.ID)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}
	if err := s.persistTokenRollout(ctx, newUser.ID, tokens, lc, ""); err != nil {
		return nil, fmt.Errorf("persist session: %w", err)
	}

	if s.auditLogger != nil {
		evt := audit.Event{
			UserID:       newUser.ID,
			Action:       "user_register",
			ResourceType: "user",
			ResourceID:   newUser.ID,
			IPAddress:    lc.IPAddress,
			UserAgent:    lc.UserAgent,
			RiskLevel:    "low",
		}
		// Solo el id del referidor (no es PII): details es JSONB sin cifrar.
		if referredBy != nil {
			evt.Details = map[string]interface{}{"referred_by": *referredBy}
		}
		s.auditLogger.Log(evt)
	}
	return &LoginResponse{User: newUser, Tokens: tokens}, nil
}

func (s *Service) ChangePassword(ctx context.Context, userID string, req *ChangePasswordRequest, lc LoginContext) error {
	u, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	// Una cuenta que entra sin contrasena no puede fijarse una: seria quedarse
	// con ella. Ver ErrCuentaDeDemostracion en internal/user.
	if u.DemoLogin {
		return ErrCuentaDeDemostracion
	}
	valid, err := hash.VerifyPin(req.OldPassword, u.PasswordHash)
	if err != nil || !valid {
		return fmt.Errorf("invalid current password")
	}
	if req.OldPassword == req.NewPassword {
		return fmt.Errorf("new password must differ from current")
	}
	newHash, err := hash.HashPin(req.NewPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	// Atomic: change the hash AND revoke every refresh family + session, or
	// nothing. A failure here must NOT leave the password changed with stale
	// sessions still valid.
	if err := s.authRepo.ChangePasswordAndRevokeSessions(ctx, userID, newHash); err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	if s.auditLogger != nil {
		s.auditLogger.LogPinChange(userID, lc.IPAddress)
	}
	return nil
}

// Refresh implements rotation with reuse detection.
func (s *Service) Refresh(ctx context.Context, refreshTokenRaw string, lc LoginContext) (*jwtpkg.TokenPair, error) {
	claims, err := s.jwt.ValidateRefresh(refreshTokenRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}
	tokenHash := jwtpkg.HashToken(refreshTokenRaw)

	// Cuenta bloqueada: se corta ANTES de consumir el token, con codigo propio.
	// `serr == nil` es a proposito: si la BD falla se sigue el camino normal,
	// que igual rechaza (el bloqueo revoca la familia en la misma tx).
	if st, serr := s.userRepo.GetStatus(ctx, claims.UserID); serr == nil && st != "active" {
		return nil, ErrAccountBlocked
	}

	rec, reused, err := s.authRepo.ConsumeRefreshToken(ctx, claims.ID, tokenHash)
	if err != nil {
		if reused {
			// Revoke all access tokens of the family by denylisting recent jtis.
			if s.auditLogger != nil {
				s.auditLogger.Log(audit.Event{
					UserID:    claims.UserID,
					Action:    "refresh_reuse_detected",
					RiskLevel: "high",
					IPAddress: lc.IPAddress,
					UserAgent: lc.UserAgent,
				})
			}
		}
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Enforce the idle and absolute session windows. The presented token's
	// issued_at is the last activity; the family origin is the original login.
	// On a violation, revoke the family so the stale token can't be retried and
	// force a fresh login.
	familyOrigin := rec.IssuedAt
	if fo, ferr := s.authRepo.FamilyOrigin(ctx, rec.FamilyID); ferr == nil && !fo.IsZero() {
		familyOrigin = fo
	}
	if sessionWindowExceeded(time.Now(), rec.IssuedAt, familyOrigin, s.idleTimeout, s.absoluteTimeout) {
		if rerr := s.authRepo.RevokeRefreshFamily(ctx, rec.FamilyID); rerr != nil {
			slog.Warn("refresh: revoke on session timeout failed", "family_id", rec.FamilyID, "err", rerr.Error())
		}
		if s.auditLogger != nil {
			s.auditLogger.Log(audit.Event{
				UserID:    rec.UserID,
				Action:    "session_timeout",
				RiskLevel: "low",
				IPAddress: lc.IPAddress,
				UserAgent: lc.UserAgent,
			})
		}
		return nil, fmt.Errorf("session timed out")
	}

	// Rotate.
	tokens, err := s.jwt.RotateRefresh(rec.UserID, rec.FamilyID, rec.JTI)
	if err != nil {
		return nil, fmt.Errorf("rotate: %w", err)
	}
	if err := s.persistTokenRollout(ctx, rec.UserID, tokens, lc, rec.JTI); err != nil {
		return nil, fmt.Errorf("persist rolled session: %w", err)
	}
	return tokens, nil
}

// Logout revokes the current access jti (Redis denylist for remaining TTL +
// session row) and the refresh family.
// ─────────────────────────────────────────────────────────────────────────
//  Sesiones abiertas: verlas y cerrarlas, una o todas
// ─────────────────────────────────────────────────────────────────────────

// ListSessions devuelve las sesiones vivas de la persona, marcando la actual.
func (s *Service) ListSessions(ctx context.Context, userID, currentJTI string) ([]SessionView, error) {
	return s.authRepo.ListActiveSessions(ctx, userID, currentJTI)
}

// RevokeSession cierra UNA sesion propia. El userID viaja hasta el WHERE, asi
// que un id de otra cuenta simplemente no encuentra nada que cerrar.
//
// Cerrar la sesion desde la que se pide esta permitido: es "salir de este
// dispositivo", y el cliente ya sabe tratar un 401.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string, lc LoginContext) (bool, error) {
	found, err := s.authRepo.RevokeSessionByID(ctx, userID, sessionID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	s.auditSession(userID, "session_revoked", lc, map[string]interface{}{"session_id": sessionID})
	return true, nil
}

// RevokeOtherSessions cierra todas las sesiones de la persona MENOS la actual:
// es el "cerrar sesion en los demas dispositivos" de toda la vida, el que se usa
// cuando uno sospecha que alguien mas entro.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, currentJTI string, lc LoginContext) (int, error) {
	n, err := s.authRepo.RevokeAllSessions(ctx, userID, currentJTI)
	if err != nil {
		return 0, err
	}
	s.auditSession(userID, "sessions_revoked_others", lc, map[string]interface{}{"count": n})
	return n, nil
}

func (s *Service) auditSession(userID, action string, lc LoginContext, details map[string]interface{}) {
	if s.auditLogger == nil {
		return
	}
	s.auditLogger.Log(audit.Event{
		UserID:       userID,
		Action:       action,
		ResourceType: "session",
		ResourceID:   userID,
		IPAddress:    lc.IPAddress,
		UserAgent:    lc.UserAgent,
		Details:      details,
		RiskLevel:    "high",
	})
}

func (s *Service) Logout(ctx context.Context, accessJTI string, accessRemainingTTL time.Duration) error {
	if accessJTI == "" {
		return nil
	}
	if err := s.authRepo.RevokeSessionByAccessJTI(ctx, accessJTI); err != nil {
		return err
	}
	if err := s.authRepo.DenylistAccessJTI(ctx, accessJTI, accessRemainingTTL); err != nil {
		return err
	}
	// Also revoke the refresh family bound to this session, if known. This is
	// best-effort (the access jti is already denylisted above), but a failure
	// must be logged rather than silently swallowed.
	var familyID *string
	if err := s.authRepo.db.QueryRow(ctx,
		`SELECT (SELECT family_id::text FROM refresh_tokens WHERE jti =
		           (SELECT refresh_jti FROM user_sessions WHERE access_jti = $1 LIMIT 1))`,
		accessJTI,
	).Scan(&familyID); err != nil {
		slog.Warn("logout: could not resolve refresh family", "access_jti", accessJTI, "err", err.Error())
	}
	if familyID != nil && *familyID != "" {
		if err := s.authRepo.RevokeRefreshFamily(ctx, *familyID); err != nil {
			slog.Warn("logout: could not revoke refresh family", "family_id", *familyID, "err", err.Error())
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
//  Password reset flow
// ─────────────────────────────────────────────────────────────────────────

// emailSendTimeout bounds a detached delivery attempt. Generous enough for a
// slow SMTP handshake, short enough that a dead provider cannot leave goroutines
// parked for minutes.
const emailSendTimeout = 30 * time.Second

// sendEmailDetached delivers on a context of its own, so a slow or unreachable
// SMTP provider cannot hold the HTTP request open.
//
// It used to send inline on the request context, which meant a provider that
// merely hung — as happened when the host blocked outbound port 587 — burned the
// whole 30-second request timeout and returned a gateway error to a user whose
// reset token had, in fact, already been issued. Delivery is best-effort by
// design: ForgotPassword must answer identically whether or not the mail goes
// out, or the response itself becomes an account-enumeration oracle.
func (s *Service) sendEmailDetached(userID, to, subject, textBody, htmlBody string) {
	ctx, cancel := context.WithTimeout(context.Background(), emailSendTimeout)
	defer cancel()
	if err := s.emailSender.SendEmail(ctx, to, subject, textBody, htmlBody); err != nil {
		slog.Warn("auth: password reset email delivery failed", "user_id", userID, "err", err.Error())
	}
}

// ForgotPassword always returns nil regardless of whether the user exists
// (anti-enumeration). When the user exists, a token is issued and stored.
// The caller is responsible for delivering the token via email/SMS.
// ForgotPassword acepta CUALQUIERA de los identificadores con los que se puede
// entrar, no solo la cedula.
//
// Antes solo aceptaba cedula, y eso ya estaba desalineado con un login que
// aceptaba tres. Con el nombre de usuario se volvio una trampa: quien entra con
// su usuario, olvida la contrasena y teclea ese usuario aqui leia "te enviamos
// instrucciones" y no le llegaba nada nunca. Un 202 que miente es peor que un
// error: el usuario espera un correo que no existe en vez de buscar otra via.
//
// Se reusa identifier.Classify —la misma regla del login— a proposito: una
// segunda regla aqui terminaria aceptando cosas distintas de las que sirven
// para entrar.
func (s *Service) ForgotPassword(ctx context.Context, identificador string, lc LoginContext) (string, error) {
	kind, canonical, cerr := identifier.Classify(identificador)
	var u *user.UserRecord
	if cerr == nil {
		u = s.resolveLoginUser(ctx, kind, canonical)
	}
	if u == nil {
		// Burn equivalent CPU so timing doesn't leak existence.
		hash.DummyVerify()
		return "", nil
	}
	raw, err := randomToken(32)
	if err != nil {
		return "", fmt.Errorf("token gen: %w", err)
	}
	h := sha256.Sum256([]byte(raw))
	tokenHash := hex.EncodeToString(h[:])
	rec := &PasswordResetTokenRecord{
		ID:          uuid.New().String(),
		UserID:      u.ID,
		TokenHash:   tokenHash,
		RequestedIP: lc.IPAddress,
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}
	if err := s.authRepo.InsertPasswordResetToken(ctx, rec); err != nil {
		return "", fmt.Errorf("insert reset token: %w", err)
	}
	// Deliver the reset token by email when configured and the user has an email
	// on file. Failure is logged but NOT surfaced: ForgotPassword must return the
	// same response whether or not delivery succeeded (anti-enumeration). Without
	// a provider the handler echoes the token in dev only.
	if s.emailSender != nil && u.Email != "" {
		subject, textBody, htmlBody := messaging.PasswordResetEmail(raw, s.publicAppURL, u.Username)
		// #nosec G118 -- intentionally detached: the request context dies with
		// the response, and delivery must outlive it (sendEmailDetached uses its
		// own bounded context).
		go s.sendEmailDetached(u.ID, u.Email, subject, textBody, htmlBody)
	}
	if s.auditLogger != nil {
		s.auditLogger.Log(audit.Event{
			UserID:    u.ID,
			Action:    "password_reset_requested",
			RiskLevel: "medium",
			IPAddress: lc.IPAddress,
			UserAgent: lc.UserAgent,
		})
	}
	return raw, nil
}

func (s *Service) ResetPassword(ctx context.Context, req *ResetPasswordRequest, lc LoginContext) error {
	h := sha256.Sum256([]byte(req.Token))
	tokenHash := hex.EncodeToString(h[:])

	userID, err := s.authRepo.ConsumePasswordResetToken(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}
	newHash, err := hash.HashPin(req.NewPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	// Atomic password change + full session/refresh revocation (see ChangePassword).
	if err := s.authRepo.ChangePasswordAndRevokeSessions(ctx, userID, newHash); err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	if s.auditLogger != nil {
		s.auditLogger.Log(audit.Event{
			UserID:    userID,
			Action:    "password_reset_completed",
			RiskLevel: "high",
			IPAddress: lc.IPAddress,
			UserAgent: lc.UserAgent,
		})
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
//  Internal helpers
// ─────────────────────────────────────────────────────────────────────────

func (s *Service) persistTokenRollout(
	ctx context.Context, userID string, tokens *jwtpkg.TokenPair, lc LoginContext, parentJTI string,
) error {
	rt := &RefreshTokenRecord{
		JTI:       tokens.RefreshJTI,
		UserID:    userID,
		FamilyID:  tokens.FamilyID,
		ParentJTI: parentJTI,
		TokenHash: jwtpkg.HashToken(tokens.RefreshToken),
		IssuedAt:  time.Now(),
		ExpiresAt: tokens.RefreshExpiry,
		IPAddress: lc.IPAddress,
		UserAgent: lc.UserAgent,
	}
	if err := s.authRepo.InsertRefreshToken(ctx, rt); err != nil {
		return err
	}
	sess := &SessionRecord{
		ID:         uuid.New().String(),
		UserID:     userID,
		AccessJTI:  tokens.AccessJTI,
		RefreshJTI: tokens.RefreshJTI,
		IPAddress:  lc.IPAddress,
		UserAgent:  lc.UserAgent,
		ExpiresAt:  tokens.RefreshExpiry,
	}
	return s.authRepo.CreateSession(ctx, sess)
}

func (s *Service) incrementLockout(kind identifier.Kind, canonical string) {
	if s.lockoutStore == nil || canonical == "" {
		return
	}
	s.lockoutStore.IncrLockout(identifier.LockoutKey(kind, canonical))
}

func (s *Service) resetLockout(kind identifier.Kind, canonical string) {
	if s.lockoutStore == nil || canonical == "" {
		return
	}
	s.lockoutStore.ResetLockout(identifier.LockoutKey(kind, canonical))
}

// Contador por cuenta (ademas del contador por identificador): la clave usa el
// user_id, que no es PII. Comparte umbral y TTL con el contador principal.
func userLockoutKey(userID string) string { return "lockout:uid:" + userID }

func (s *Service) incrementUserLockout(userID string) {
	if s.lockoutStore == nil || userID == "" {
		return
	}
	s.lockoutStore.IncrLockout(userLockoutKey(userID))
}

func (s *Service) resetUserLockout(userID string) {
	if s.lockoutStore == nil || userID == "" {
		return
	}
	s.lockoutStore.ResetLockout(userLockoutKey(userID))
}

func (s *Service) isUserLockedOut(userID string) bool {
	if s.lockoutStore == nil || userID == "" {
		return false
	}
	return int(s.lockoutStore.GetLockout(userLockoutKey(userID))) >= s.maxLoginAttempts
}

// ─────────────────────────────────────────────────────────────────────────
//  Registration phone verification (OTP)
// ─────────────────────────────────────────────────────────────────────────

// SendRegistrationOTP generates a 6-digit code for a phone, stores its hash
// (short TTL, attempt-capped) and returns the plaintext code. Delivery is out
// of band: a production SMS provider would send it; with none wired the handler
// echoes it only in dev (mirroring ForgotPassword's dev_token).
func (s *Service) SendRegistrationOTP(ctx context.Context, phone, email string) (string, error) {
	if phone == "" {
		return "", fmt.Errorf("phone required")
	}
	code, err := generateNumericOTP(6)
	if err != nil {
		return "", fmt.Errorf("generate code: %w", err)
	}
	// Entrega por correo primero: es el canal real hoy (SES). El envio es
	// sincrono a proposito — a diferencia de ForgotPassword no hay anti-
	// enumeracion que proteger (el telefono aun no es una cuenta) y un fallo
	// de entrega debe llegarle al cliente para que ofrezca reintentar, no
	// dejarlo esperando un codigo que nunca va a llegar.
	if email != "" && s.emailSender != nil {
		// El registro del codigo lleva el HASH del correo canonico al que se
		// envio: probar el codigo probara posesion de ese buzon, y Register
		// compara ese hash para marcar email_verified. Se guarda hasheado (no
		// en claro) y ANTES de enviar, para que no exista ventana en la que el
		// codigo llegue y no se pueda verificar.
		if err := s.authRepo.PutRegistrationOTP(ctx, phone, hashOTP(code), hashCorreoCanonico(email)); err != nil {
			return "", fmt.Errorf("store otp: %w", err)
		}
		subject, textBody, htmlBody := messaging.RegistrationOTPEmail(code)
		if err := s.emailSender.SendEmail(ctx, email, subject, textBody, htmlBody); err != nil {
			return "", fmt.Errorf("deliver otp: %w", err)
		}
		return code, nil
	}
	// Canal SMS o eco en dev: el codigo no prueba nada sobre el correo.
	if err := s.authRepo.PutRegistrationOTP(ctx, phone, hashOTP(code), ""); err != nil {
		return "", fmt.Errorf("store otp: %w", err)
	}
	// Respaldo por SMS cuando haya proveedor. Sin ninguno de los dos, el
	// handler hace eco del codigo solo en desarrollo.
	if s.smsSender != nil {
		if err := s.smsSender.SendSMS(ctx, phone, messaging.VerificationSMS(code)); err != nil {
			return "", fmt.Errorf("deliver otp: %w", err)
		}
	}
	return code, nil
}

// VerifyRegistrationOTP checks a code and, on success, issues a short-lived,
// single-use phone-verification token that Register consumes.
func (s *Service) VerifyRegistrationOTP(ctx context.Context, phone, code string) (string, error) {
	if phone == "" || code == "" {
		return "", ErrInvalidOTP
	}
	ok, verifiedEmailHash, err := s.authRepo.VerifyRegistrationOTP(ctx, phone, hashOTP(code))
	if err != nil {
		return "", fmt.Errorf("verify otp: %w", err)
	}
	if !ok {
		return "", ErrInvalidOTP
	}
	token, err := randomToken(32)
	if err != nil {
		return "", fmt.Errorf("token gen: %w", err)
	}
	if err := s.authRepo.PutPhoneVerificationToken(ctx, token, phone, verifiedEmailHash); err != nil {
		return "", fmt.Errorf("store verify token: %w", err)
	}
	return token, nil
}

// hashCorreoCanonico devuelve un hash estable del correo en su forma canonica
// (lower/trim). Se guarda esto en Redis en vez del correo en claro; el unico
// consumidor (Register) solo necesita una comparacion de igualdad. Cadena
// vacia entra y sale vacia (canal SMS, sin correo).
func hashCorreoCanonico(email string) string {
	canon := strings.ToLower(strings.TrimSpace(email))
	if canon == "" {
		return ""
	}
	h := sha256.Sum256([]byte("regemail:" + canon))
	return hex.EncodeToString(h[:])
}

// isUsersUniqueViolation reporta un choque de unicidad al insertar el usuario
// (cedula, telefono o correo ya registrados). El choque del codigo de referido
// se excluye: el repositorio ya lo reintenta y, si aun asi falla, es un error
// interno y no "usuario existente". Se decide por SQLSTATE y no por nombre de
// indice porque el esquema de pruebas nombra los suyos distinto al de
// produccion (users_phone_hash_key vs uq_users_phone_hash).
func isUsersUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName != "uq_users_referral_code"
}

// soloDigitos deja unicamente los digitos de una cedula tecleada con guiones o
// espacios; es la misma canonica que aplica pkg/identifier en el login.
func soloDigitos(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hashOTP(code string) string {
	h := sha256.Sum256([]byte("regotp:" + code))
	return hex.EncodeToString(h[:])
}

// generateNumericOTP returns an n-digit numeric string using crypto/rand.
func generateNumericOTP(n int) (string, error) {
	const digits = "0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}
	return string(b), nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
