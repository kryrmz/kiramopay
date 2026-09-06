package user_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kiramopay/backend/internal/testutil"
	"github.com/kiramopay/backend/internal/user"
	"github.com/kiramopay/backend/pkg/hash"
)

// LA CADENA QUE ESTO CORTA: el correo es el destino del enlace de recuperacion.
// Cambiarlo no pedia nada mas que una sesion, asi que quien consiguiera una
// podia apuntarlo a su propio buzon, pedir recuperacion, fijarse una contrasena
// nueva y quedarse con la cuenta PARA SIEMPRE — expulsando al duenno, porque el
// reset revoca todas sus sesiones.
//
// Se pide la contrasena vigente y NO que el correo este verificado: exigir lo
// segundo dejaria sin recuperacion a quien cambio su correo y despues olvido la
// contrasena. Esto no le quita el camino a nadie que sepa su contrasena.
func setup(t *testing.T) (*user.Service, string) {
	t.Helper()
	pool := testutil.TestDB(t)
	pin, err := hash.HashPin("Kiramopay2024!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	id := testutil.SeedTestUser(t, pool, "702650930", pin)
	return user.NewService(user.NewRepository(pool)), id
}

func TestUpdateProfile_CambiarElCorreoExigeLaContrasena(t *testing.T) {
	svc, id := setup(t)
	nuevo := "atacante@evil.com"

	// Sin contrasena.
	if _, err := svc.UpdateProfile(context.Background(), id,
		&user.UpdateProfileRequest{Email: &nuevo}); !errors.Is(err, user.ErrContrasenaRequerida) {
		t.Fatalf("sin contrasena = %v, esperaba ErrContrasenaRequerida", err)
	}
	// Con una equivocada.
	if _, err := svc.UpdateProfile(context.Background(), id,
		&user.UpdateProfileRequest{Email: &nuevo, CurrentPassword: "otraClave1!"}); !errors.Is(err, user.ErrContrasenaRequerida) {
		t.Fatalf("con contrasena equivocada = %v, esperaba ErrContrasenaRequerida", err)
	}
	// Y con la correcta si cambia: no se le quita el camino a quien la sabe.
	if _, err := svc.UpdateProfile(context.Background(), id,
		&user.UpdateProfileRequest{Email: &nuevo, CurrentPassword: "Kiramopay2024!"}); err != nil {
		t.Fatalf("con la contrasena correcta: %v", err)
	}
}

// El resto del perfil no mueve esa puerta y sigue sin pedir nada: cobrarle la
// contrasena a quien solo corrige su apellido seria molestar sin motivo.
func TestUpdateProfile_ElRestoDelPerfilNoPideContrasena(t *testing.T) {
	svc, id := setup(t)
	nombre := "Keilor"
	if _, err := svc.UpdateProfile(context.Background(), id,
		&user.UpdateProfileRequest{FirstName: &nombre}); err != nil {
		t.Fatalf("cambiar el nombre pidio contrasena: %v", err)
	}
}
