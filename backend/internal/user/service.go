package user

import (
	"github.com/kiramopay/backend/pkg/hash"
	"strings"
	"errors"
	"context"
	"fmt"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) GetProfile(ctx context.Context, userID string) (*UserRecord, error) {
	u, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return u, nil
}

// ErrCuentaDeDemostracion: se intento cambiar la identidad o las credenciales
// de una cuenta que entra SIN CONTRASENA (users.demo_login).
//
// Esto corta una cadena concreta de tres pasos: quien entra sin contrasena
// cambia el correo de la cuenta, pide un enlace de recuperacion —que se manda
// al correo que este en la fila—, y se queda con la contrasena. A partir de
// ahi la cuenta es suya PARA SIEMPRE: apagar la bandera de demostracion ya no
// la recupera. Una cuenta de demostracion es un accesorio, no la cuenta de una
// persona: no tiene por que poder cambiar su propia identidad.
var ErrCuentaDeDemostracion = errors.New("una cuenta de demostracion no puede cambiar su identidad ni su contrasena")

// ErrContrasenaRequerida: se intento cambiar el correo sin presentar la
// contrasena vigente, o presentando una equivocada.
var ErrContrasenaRequerida = errors.New("se requiere la contrasena vigente para cambiar el correo")

func (s *Service) UpdateProfile(ctx context.Context, userID string, req *UpdateProfileRequest) (*UserRecord, error) {
	actual, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if actual.DemoLogin {
		return nil, ErrCuentaDeDemostracion
	}
	// Cambiar el correo exige la contrasena vigente. Es el destino del enlace de
	// recuperacion: quien lo cambia puede fijarse una contrasena nueva y quedarse
	// con la cuenta, expulsando al duenno (el reset revoca todas sus sesiones).
	// El resto de los campos del perfil no mueven esa puerta y siguen sin pedir
	// nada.
	if req.Email != nil && strings.TrimSpace(*req.Email) != actual.Email {
		valido, err := hash.VerifyPin(req.CurrentPassword, actual.PasswordHash)
		if err != nil || !valido {
			return nil, ErrContrasenaRequerida
		}
	}
	if err := s.repo.UpdateProfile(ctx, userID, req); err != nil {
		return nil, fmt.Errorf("update profile: %w", err)
	}
	return s.repo.FindByID(ctx, userID)
}
