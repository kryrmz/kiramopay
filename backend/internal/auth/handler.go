package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kiramopay/backend/internal/middleware"
	"github.com/kiramopay/backend/internal/user"
	"github.com/kiramopay/backend/pkg/identifier"
	"github.com/kiramopay/backend/pkg/response"
	"github.com/kiramopay/backend/pkg/validator"
)

type Handler struct {
	service *Service
	cookies CookieConfig
	devMode bool // server runs in development; gates the dev-token echo
}

func NewHandler(service *Service, cookies CookieConfig, devMode bool) *Handler {
	return &Handler{service: service, cookies: cookies, devMode: devMode}
}

// noStore marks an auth response uncacheable so tokens are never written to a
// shared or browser cache (OWASP).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

func loginContext(r *http.Request) LoginContext {
	// La IP se valida antes de salir: acaba en NULLIF($6,'')::inet al crear la
	// sesion, y un valor no parseable —"unknown" es real, lo emiten varios
	// proxies corporativos— hacia fallar el INSERT, luego CreateSession, luego
	// Login, y el handler respondia 401 "invalid credentials". Es decir, dejaba
	// sin poder entrar a quien pasara por ese proxy, con un mensaje que apuntaba
	// al lado equivocado. Si no hay IP utilizable se guarda NULL.
	return LoginContext{
		IPAddress: middleware.RequestIP(r),
		UserAgent: r.UserAgent(),
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	// Un solo campo, tres formas: cedula, correo o telefono. El mensaje del 400
	// es generico a proposito — no revela que forma fallo ni cuales existen.
	if _, _, err := identifier.Classify(req.EffectiveIdentifier()); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid identifier")
		return
	}
	// Login must NOT enforce the password-complexity policy — that belongs to
	// registration. Re-validating here locks out any account whose password
	// predates a policy change or was provisioned by the seeder. The service
	// verifies the hash and returns a constant "invalid credentials" on mismatch.

	result, err := h.service.Login(r.Context(), &req, loginContext(r))
	if err != nil {
		// Cuenta bloqueada: 403 con codigo propio para que el cliente lo
		// muestre. Solo se llega aqui con la contrasena correcta (Service.Login).
		if errors.Is(err, ErrAccountBlocked) {
			noStore(w)
			response.Error(w, http.StatusForbidden, "ACCOUNT_BLOCKED", "account blocked")
			return
		}
		// La cuenta si pide contrasena. Codigo propio para que la pantalla la
		// pida, en vez de mostrar "credenciales incorrectas" antes de que el
		// usuario haya escrito nada.
		//
		// No filtra si la cuenta existe: el servicio devuelve ESTE mismo error
		// para un identificador que no corresponde a ninguna cuenta. Si
		// distinguiera, comparar los dos codigos convertiria esta ruta —publica
		// y sin gastar intentos— en un listador de cuentas.
		if errors.Is(err, ErrPasswordRequired) {
			noStore(w)
			response.Error(w, http.StatusUnauthorized, "PASSWORD_REQUIRED", "password required")
			return
		}
		// Log the real cause for ops; the client always sees a constant
		// "invalid credentials" message (constant-time anti-enumeration).
		if !errors.Is(err, ErrInvalidCredentials) {
			slog.Error("login: internal error", "err", err.Error())
		}
		response.Error(w, http.StatusUnauthorized, "AUTH_FAILED", "invalid credentials")
		return
	}
	// Issue the refresh token as an HttpOnly cookie (the secure transport). The
	// body still carries the tokens for backward compatibility with clients that
	// have not migrated to the cookie yet.
	h.cookies.setRefreshCookie(w, result.Tokens.RefreshToken, result.Tokens.RefreshExpiry)
	noStore(w)
	response.JSON(w, http.StatusOK, result)
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	var errs validator.ValidationErrors
	if err := validator.ValidateCedula(req.Cedula); err != nil {
		errs = append(errs, *err)
	}
	if err := validator.ValidatePhone(req.Phone); err != nil {
		errs = append(errs, *err)
	}
	if err := validator.ValidatePassword(req.Password); err != nil {
		errs = append(errs, *err)
	}
	if err := validator.ValidateRequired("first_name", req.FirstName); err != nil {
		errs = append(errs, *err)
	}
	if err := validator.ValidateRequired("last_name", req.LastName); err != nil {
		errs = append(errs, *err)
	}
	if errs.HasErrors() {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", errs.Error())
		return
	}
	// Codigo de invitacion (opcional): aqui se normaliza y se valida la FORMA;
	// que exista en una cuenta activa lo decide el servicio. Un codigo mal
	// formado nunca llega a la BD.
	if req.ReferralCode != "" {
		req.ReferralCode = user.NormalizeReferralCode(req.ReferralCode)
		if req.ReferralCode != "" && !user.IsValidReferralCodeFormat(req.ReferralCode) {
			response.Error(w, http.StatusBadRequest, "REFERRAL_CODE_INVALID", "codigo de invitacion invalido")
			return
		}
	}

	result, err := h.service.Register(r.Context(), &req, loginContext(r))
	if err != nil {
		status, code, message := registerErrorResponse(err)
		if status >= http.StatusInternalServerError {
			// La causa real solo va al log (sin IP ni user-agent). response.Error
			// ya reemplaza el mensaje de todo 5xx por uno generico: el cliente
			// decide por el codigo, nunca por el texto.
			slog.Error("register: internal error", "err", err.Error())
		}
		response.Error(w, status, code, message)
		return
	}
	h.cookies.setRefreshCookie(w, result.Tokens.RefreshToken, result.Tokens.RefreshExpiry)
	noStore(w)
	response.JSON(w, http.StatusCreated, result)
}

// registerFailedMessage es el texto del 500 REGISTER_FAILED antes de pasar por
// response.Error, que lo sustituye por su generico: el cliente nunca ve el
// error interno (texto de BD, invariantes), que solo va al log.
const registerFailedMessage = "no se pudo completar el registro"

// registerErrorResponse traduce el error de Service.Register al contrato de
// POST /auth/register: estado, codigo y mensaje para el cliente. Todo lo que
// no sea un error sentinela del servicio es un 500 REGISTER_FAILED.
func registerErrorResponse(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, ErrUserExists):
		return http.StatusConflict, "USER_EXISTS", "ya existe una cuenta con esa cedula, telefono o correo"
	case errors.Is(err, ErrPhoneNotVerified):
		return http.StatusForbidden, "PHONE_NOT_VERIFIED", "falta verificar el telefono o la verificacion vencio"
	case errors.Is(err, ErrCedulaNoUsableEnLogin):
		return http.StatusBadRequest, "CEDULA_INVALID", "cedula no utilizable para iniciar sesion"
	case errors.Is(err, ErrReferralCodeInvalid):
		return http.StatusBadRequest, "REFERRAL_CODE_INVALID", "codigo de invitacion invalido"
	case errors.Is(err, ErrUsernameInvalido):
		return http.StatusBadRequest, "USERNAME_INVALID", "nombre de usuario no valido"
	// A diferencia del choque de cedula o telefono —que se colapsan en un
	// USER_EXISTS generico para no confirmar que ese dato esta registrado—, un
	// nombre de usuario tomado SI se dice: es publico por naturaleza y quien
	// se registra necesita saber que elegir otro.
	case errors.Is(err, ErrUsernameTomado):
		return http.StatusConflict, "USERNAME_TAKEN", "ese nombre de usuario ya esta en uso"
	default:
		return http.StatusInternalServerError, "REGISTER_FAILED", registerFailedMessage
	}
}

// RegisterSendOTP issues a verification code for a pending registration and
// delivers it to the given email (SES). SMS remains the fallback for whenever
// a provider is wired. In dev the code is also echoed (dev_code) like
// ForgotPassword so local flows work without a mail sandbox.
func (h *Handler) RegisterSendOTP(w http.ResponseWriter, r *http.Request) {
	var req SendRegistrationOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if err := validator.ValidatePhone(req.Phone); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Message)
		return
	}
	// El correo es obligatorio: es adonde viaja el codigo. Aceptarlo vacio
	// volveria al estado anterior — un codigo generado que no le llega a nadie.
	// (ValidateEmail trata el vacio como opcional, por eso el chequeo aparte.)
	if req.Email == "" {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "email is required")
		return
	}
	if err := validator.ValidateEmail(req.Email); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Message)
		return
	}
	code, err := h.service.SendRegistrationOTP(r.Context(), req.Phone, req.Email)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "OTP_SEND_FAILED", "could not send verification code")
		return
	}
	resp := map[string]string{"message": "verification code sent"}
	if h.isDevMode(r) {
		resp["dev_code"] = code
	}
	noStore(w)
	response.JSON(w, http.StatusOK, resp)
}

// RegisterVerifyOTP checks the code and returns a single-use verification token
// the client passes to /auth/register as `verification_token`.
func (h *Handler) RegisterVerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req VerifyRegistrationOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	token, err := h.service.VerifyRegistrationOTP(r.Context(), req.Phone, req.Code)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "OTP_INVALID", "invalid or expired verification code")
		return
	}
	noStore(w)
	response.JSON(w, http.StatusOK, map[string]string{"verification_token": token})
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Prefer the HttpOnly cookie (the secure path); fall back to the JSON body so
	// clients that have not migrated to the cookie keep working.
	refreshRaw := h.cookies.refreshTokenFromCookie(r)
	fromCookie := refreshRaw != ""
	if !fromCookie {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
			response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
			return
		}
		refreshRaw = req.RefreshToken
	}
	tokens, err := h.service.Refresh(r.Context(), refreshRaw, loginContext(r))
	if err != nil {
		// A cookie-borne token that no longer validates is stale — clear it so the
		// browser stops replaying it on every request.
		if fromCookie {
			h.cookies.clearRefreshCookie(w)
		}
		noStore(w)
		// Cuenta bloqueada: la cookie tambien se limpia (sus sesiones ya estan
		// revocadas) y el cliente recibe el codigo distinguible.
		if errors.Is(err, ErrAccountBlocked) {
			response.Error(w, http.StatusForbidden, "ACCOUNT_BLOCKED", "account blocked")
			return
		}
		response.Error(w, http.StatusUnauthorized, "REFRESH_FAILED", "invalid refresh token")
		return
	}
	h.cookies.setRefreshCookie(w, tokens.RefreshToken, tokens.RefreshExpiry)
	noStore(w)
	response.JSON(w, http.StatusOK, tokens)
}

// Sessions — GET /api/v1/auth/sessions
//
// Las sesiones abiertas de quien pregunta, con la actual marcada. No lleva
// tokens ni hashes: solo lo que sirve para reconocer un dispositivo y decidir
// cerrarlo.
func (h *Handler) Sessions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	noStore(w)
	sesiones, err := h.service.ListSessions(r.Context(), userID, middleware.GetAccessJTI(r.Context()))
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "SESSIONS_FAILED", err.Error())
		return
	}
	response.JSON(w, http.StatusOK, sesiones)
}

// RevokeSession — POST /api/v1/auth/sessions/{id}/revoke
//
// Cierra un dispositivo propio. Un id que no sea de esta cuenta no encuentra
// nada que cerrar y devuelve 404, sin decir si existe en otra parte.
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_ID", "id must be a UUID")
		return
	}
	found, err := h.service.RevokeSession(r.Context(), userID, id.String(), loginContext(r))
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
		return
	}
	if !found {
		response.Error(w, http.StatusNotFound, "SESSION_NOT_FOUND", "session not found")
		return
	}
	response.JSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// RevokeOtherSessions — POST /api/v1/auth/sessions/revoke-others
//
// Cierra todos los demas dispositivos y deja vivo el actual: el boton de "me
// parece que alguien mas entro en mi cuenta".
func (h *Handler) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	n, err := h.service.RevokeOtherSessions(r.Context(), userID, middleware.GetAccessJTI(r.Context()), loginContext(r))
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
		return
	}
	response.JSON(w, http.StatusOK, map[string]int{"revoked": n})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// Clear the session cookie and ask the browser to drop cached site data,
	// regardless of the backend revocation outcome below — the client intends to
	// be logged out.
	h.cookies.clearRefreshCookie(w)
	w.Header().Set("Clear-Site-Data", `"cookies", "storage"`)
	noStore(w)

	jti := middleware.GetAccessJTI(r.Context())
	exp := middleware.GetAccessExp(r.Context())
	var ttl time.Duration
	if exp > 0 {
		ttl = time.Until(time.Unix(exp, 0))
		if ttl <= 0 {
			ttl = time.Second
		}
	} else {
		ttl = 15 * time.Minute
	}
	if err := h.service.Logout(r.Context(), jti, ttl); err != nil {
		response.Error(w, http.StatusInternalServerError, "LOGOUT_FAILED", "could not log out")
		return
	}
	response.NoContent(w)
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "user not authenticated")
		return
	}
	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if err := validator.ValidatePassword(req.NewPassword); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Message)
		return
	}
	if err := h.service.ChangePassword(r.Context(), userID, &req, loginContext(r)); err != nil {
		if errors.Is(err, ErrCuentaDeDemostracion) {
			response.Error(w, http.StatusForbidden, "DEMO_ACCOUNT",
				"una cuenta de demostracion no puede cambiar su contrasena")
			return
		}
		response.Error(w, http.StatusBadRequest, "CHANGE_PASSWORD_FAILED", err.Error())
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

// ForgotPassword issues a reset token. Response is constant ("OK") to prevent
// enumeration; in dev mode, the token is returned for testing convenience.
func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	// La forma se comprueba con LA MISMA regla del login. Antes se exigia
	// ValidateCedula y, al fallar, se respondia 202 sin consultar nada: quien
	// tecleara su correo o su nombre de usuario leia "te enviamos
	// instrucciones" y no le llegaba nada nunca.
	if _, _, err := identifier.Classify(req.EffectiveIdentifier()); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid identifier")
		return
	}
	token, err := h.service.ForgotPassword(r.Context(), req.EffectiveIdentifier(), loginContext(r))
	if err != nil {
		// Still return generic — never leak internal errors here.
		response.JSON(w, http.StatusAccepted, map[string]string{"message": "if the account exists, a reset link has been sent"})
		return
	}
	resp := map[string]string{"message": "if the account exists, a reset link has been sent"}
	if token != "" && h.isDevMode(r) {
		resp["dev_token"] = token
	}
	response.JSON(w, http.StatusAccepted, resp)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if err := validator.ValidatePassword(req.NewPassword); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Message)
		return
	}
	if err := h.service.ResetPassword(r.Context(), &req, loginContext(r)); err != nil {
		response.Error(w, http.StatusBadRequest, "RESET_FAILED", "invalid or expired reset token")
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{"message": "Password reset successful"})
}

// isDevMode reports whether the dev-only token echo is allowed. It is gated on
// the SERVER's environment (set at construction from config) — the request
// header alone is never trusted, so a client cannot turn on dev mode in
// production and exfiltrate the reset token.
func (h *Handler) isDevMode(r *http.Request) bool {
	return h.devMode && r.Header.Get("X-Kiramopay-Dev") == "true"
}
