package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kiramopay/backend/internal/auth"
	"github.com/kiramopay/backend/internal/middleware"
	"github.com/kiramopay/backend/internal/testutil"
	"github.com/kiramopay/backend/internal/user"
	"github.com/kiramopay/backend/internal/wallet"
	"github.com/kiramopay/backend/pkg/hash"
	jwtpkg "github.com/kiramopay/backend/pkg/jwt"
)

// servicioConDemo arma el servicio con la bandera de entrada sin contrasena en
// el estado que pida la prueba, y devuelve tambien el pool para marcar cuentas.
func servicioConDemo(t *testing.T, encendida bool) (*auth.Service, *pgxpool.Pool, middleware.LockoutStore) {
	t.Helper()
	pool := testutil.TestDB(t)
	redis := testutil.TestRedis(t)
	lockoutStore := middleware.NewRedisLockoutStore(redis, time.Minute)
	svc := auth.NewService(
		auth.NewRepository(pool, redis),
		user.NewRepository(pool),
		wallet.NewRepository(pool),
		jwtpkg.NewManager("test-secret-key", 15*time.Minute, 7*24*time.Hour),
		&auth.Options{LockoutStore: lockoutStore, DemoLoginEnabled: encendida},
	)
	return svc, pool, lockoutStore
}

// sembrarConUsuario crea una cuenta y le pone nombre de usuario, marcandola o
// no como cuenta de demostracion.
func sembrarConUsuario(t *testing.T, pool *pgxpool.Pool, cedula, username string, demo bool) string {
	t.Helper()
	pinHash, err := hash.HashPin("Kiramopay2024!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	id := testutil.SeedTestUser(t, pool, cedula, pinHash)
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET username = $2, demo_login = $3 WHERE id = $1::uuid`, id, username, demo); err != nil {
		t.Fatalf("marcar cuenta: %v", err)
	}
	return id
}

// Lo que el dueno pidio: teclear el nombre de usuario y entrar, sin contrasena.
func TestLogin_CuentaDeDemoEntraSinContrasena(t *testing.T) {
	svc, pool, _ := servicioConDemo(t, true)
	sembrarConUsuario(t, pool, "702650930", "demo", true)

	res, err := svc.Login(context.Background(),
		&auth.LoginRequest{Identifier: "demo", Password: ""}, emptyCtx)
	if err != nil {
		t.Fatalf("la cuenta de demostracion no entro sin contrasena: %v", err)
	}
	if res.Tokens.AccessToken == "" {
		t.Fatal("no se emitio sesion")
	}
	// Y el nombre de usuario tambien sirve CON contrasena, como cualquier otro
	// identificador.
	if _, err := svc.Login(context.Background(),
		&auth.LoginRequest{Identifier: "demo", Password: "Kiramopay2024!"}, emptyCtx); err != nil {
		t.Fatalf("el nombre de usuario no sirve con contrasena: %v", err)
	}
}

// La bandera apagada es la palanca: la misma cuenta marcada deja de abrirse.
func TestLogin_ConLaBanderaApagadaNadieEntraSinContrasena(t *testing.T) {
	svc, pool, _ := servicioConDemo(t, false)
	sembrarConUsuario(t, pool, "702650930", "demo", true)

	_, err := svc.Login(context.Background(),
		&auth.LoginRequest{Identifier: "demo", Password: ""}, emptyCtx)
	if !errors.Is(err, auth.ErrPasswordRequired) {
		t.Fatalf("con la bandera apagada dio %v, esperaba ErrPasswordRequired", err)
	}
}

// Una cuenta que NO esta marcada no se abre nunca sin contrasena, ni con la
// bandera encendida.
func TestLogin_UnaCuentaNoMarcadaNoAbreSinContrasena(t *testing.T) {
	svc, pool, _ := servicioConDemo(t, true)
	sembrarConUsuario(t, pool, "702650930", "keilor", false)

	_, err := svc.Login(context.Background(),
		&auth.LoginRequest{Identifier: "keilor", Password: ""}, emptyCtx)
	if !errors.Is(err, auth.ErrPasswordRequired) {
		t.Fatalf("una cuenta sin marcar dio %v, esperaba ErrPasswordRequired", err)
	}
}

// EL DEFECTO QUE ESTA GUARDA CIERRA: la pantalla sondea con la contrasena
// vacia para saber si tiene que pedirla. Si ese sondeo contara como intento
// fallido, cinco pulsaciones de Enter sobre el campo del identificador
// dejarian la cuenta bloqueada 15 minutos sin que nadie escribiera nada.
func TestLogin_ElSondeoSinContrasenaNoGastaIntentos(t *testing.T) {
	svc, pool, store := servicioConDemo(t, true)
	sembrarConUsuario(t, pool, "702650930", "keilor", false)

	for i := 0; i < 6; i++ {
		if _, err := svc.Login(context.Background(),
			&auth.LoginRequest{Identifier: "keilor", Password: ""}, emptyCtx); !errors.Is(err, auth.ErrPasswordRequired) {
			t.Fatalf("intento %d: %v", i+1, err)
		}
	}

	// Seis sondeos despues, la contrasena correcta tiene que entrar igual.
	if _, err := svc.Login(context.Background(),
		&auth.LoginRequest{Identifier: "keilor", Password: "Kiramopay2024!"}, emptyCtx); err != nil {
		t.Fatalf("la cuenta quedo bloqueada por los sondeos: %v", err)
	}
	_ = store
}

// Una contrasena EQUIVOCADA si tiene que contar: el sondeo no puede volverse
// una forma de probar contrasenas sin limite.
func TestLogin_UnaContrasenaEquivocadaSiGastaIntentos(t *testing.T) {
	svc, pool, _ := servicioConDemo(t, true)
	sembrarConUsuario(t, pool, "702650930", "keilor", false)

	for i := 0; i < 5; i++ {
		if _, err := svc.Login(context.Background(),
			&auth.LoginRequest{Identifier: "keilor", Password: "loQueSea1!"}, emptyCtx); err == nil {
			t.Fatalf("intento %d entro con contrasena equivocada", i+1)
		}
	}
	// Agotados los intentos, ni la contrasena correcta entra.
	if _, err := svc.Login(context.Background(),
		&auth.LoginRequest{Identifier: "keilor", Password: "Kiramopay2024!"}, emptyCtx); err == nil {
		t.Fatal("el contador de intentos no freno nada")
	}
}

// El nombre de usuario no puede servir para bloquear a OTRA cuenta. Con el
// contador tipado, fallar contra un usuario no toca el contador de ninguna
// cedula, telefono ni correo de nadie mas.
//
// Nota deliberada sobre lo que SI pasa: el contador POR CUENTA no lleva tipo, y
// eso es correcto — existe justamente para que una cuenta no reciba cinco
// intentos por cada puerta. Fallar cinco veces contra "victor" bloquea a Victor
// en sus cuatro puertas, y eso es lo que se quiere. Lo que cambia con el nombre
// de usuario es que ahora esa puerta es adivinable, asi que bloquear a alguien
// a proposito es mas facil que antes. Es el precio de que el login sea comodo,
// y queda escrito aqui para que sea una decision y no una sorpresa.
func TestLogin_FallarContraUnUsuarioNoBloqueaAOtraCuenta(t *testing.T) {
	svc, pool, _ := servicioConDemo(t, true)
	sembrarConUsuario(t, pool, "702650930", "victor", false)
	// Segunda cuenta, con su propia cedula y su propio nombre de usuario.
	otra := testutil.SeedTestUser2(t, pool)
	pinHash, err := hash.HashPin("Kiramopay2024!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET username = 'keilor', password_hash = $2 WHERE id = $1::uuid`,
		otra, pinHash); err != nil {
		t.Fatalf("preparar la segunda cuenta: %v", err)
	}

	for i := 0; i < 6; i++ {
		_, _ = svc.Login(context.Background(),
			&auth.LoginRequest{Identifier: "victor", Password: "malaClave1!"}, emptyCtx)
	}

	// La otra cuenta entra sin problema: los contadores no se cruzan.
	if _, err := svc.Login(context.Background(),
		&auth.LoginRequest{Identifier: "keilor", Password: "Kiramopay2024!"}, emptyCtx); err != nil {
		t.Fatalf("bloquear a una cuenta dejo fuera a otra distinta: %v", err)
	}
}

// EL ORACULO QUE ESTO CIERRA: el sondeo con contrasena vacia respondia
// PASSWORD_REQUIRED cuando la cuenta existia y AUTH_FAILED cuando no. Dos
// codigos distintos, en una ruta publica que ademas no gasta intentos, es un
// listador de cuentas: se puede comprobar una por una que cedulas, telefonos,
// correos y nombres de usuario tienen cuenta en KiramoPay.
//
// Todo el resto de Login esta construido para no filtrar eso. Esta rama tiene
// que respetarlo igual.
func TestLogin_ElSondeoNoDiceSiLaCuentaExiste(t *testing.T) {
	for _, bandera := range []bool{false, true} {
		t.Run(map[bool]string{false: "bandera apagada", true: "bandera encendida"}[bandera], func(t *testing.T) {
			svc, pool, _ := servicioConDemo(t, bandera)
			sembrarConUsuario(t, pool, "702650930", "keilor", false)
			ctx := context.Background()

			_, errExiste := svc.Login(ctx, &auth.LoginRequest{Identifier: "keilor", Password: ""}, emptyCtx)
			_, errNoExiste := svc.Login(ctx, &auth.LoginRequest{Identifier: "noexiste", Password: ""}, emptyCtx)

			if !errors.Is(errExiste, auth.ErrPasswordRequired) {
				t.Fatalf("cuenta existente: %v, esperaba ErrPasswordRequired", errExiste)
			}
			if !errors.Is(errNoExiste, auth.ErrPasswordRequired) {
				t.Fatalf("cuenta inexistente: %v — el codigo distinto delata que la otra SI existe", errNoExiste)
			}
		})
	}
}
