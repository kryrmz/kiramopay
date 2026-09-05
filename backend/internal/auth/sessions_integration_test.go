package auth_test

import (
	"context"
	"testing"

	"github.com/kiramopay/backend/internal/auth"
)

// ─────────────────────────────────────────────────────────────────────────
//  Cerrar sesion por dispositivo
//
//  Lo que hay que probar de verdad no es que la fila quede marcada, sino que
//  el dispositivo cerrado NO pueda volver: su familia de refresh tiene que
//  morir con el. Si sobrevive, el aparato renueva en cuanto vence el token de
//  acceso -quince minutos- y la sesion se veria cerrada sin estarlo.
// ─────────────────────────────────────────────────────────────────────────

// entrar abre una sesion nueva, como lo haria otro dispositivo.
func entrar(t *testing.T, env entornoBloqueo) *auth.LoginResponse {
	t.Helper()
	resp, err := env.svc.Login(context.Background(), &auth.LoginRequest{
		Identifier: "702650930", Password: "Kiramopay2024!",
	}, auth.LoginContext{IPAddress: "10.0.0.1", UserAgent: "Pruebas"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return resp
}

func refreshVivos(t *testing.T, env entornoBloqueo, userID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM refresh_tokens WHERE user_id = $1::uuid AND revoked_at IS NULL`,
		userID).Scan(&n); err != nil {
		t.Fatalf("contar refresh vivos: %v", err)
	}
	return n
}

func TestListActiveSessions_UnaPorDispositivo(t *testing.T) {
	env := armarEntornoBloqueo(t)
	ctx := context.Background()
	primera := registerTestUser(t, env.svc)
	entrar(t, env)
	entrar(t, env)

	sesiones, err := env.authRepo.ListActiveSessions(ctx, primera.User.ID, primera.Tokens.AccessJTI)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(sesiones) != 3 {
		t.Fatalf("sesiones = %d, esperaba 3 (el registro y dos ingresos)", len(sesiones))
	}

	var actuales int
	for _, s := range sesiones {
		if s.Current {
			actuales++
		}
		// Nada de tokens ni hashes en lo que se muestra.
		if s.ID == "" || s.ExpiresAt.IsZero() {
			t.Fatalf("sesion incompleta: %+v", s)
		}
	}
	if actuales != 1 {
		t.Fatalf("sesiones marcadas como actual = %d, esperaba exactamente 1", actuales)
	}
}

func TestRevokeSessionByID_MataTambienSuFamiliaDeRefresh(t *testing.T) {
	env := armarEntornoBloqueo(t)
	ctx := context.Background()
	uno := registerTestUser(t, env.svc)
	dos := entrar(t, env)

	antes := refreshVivos(t, env, uno.User.ID)
	if antes != 2 {
		t.Fatalf("familias vivas antes = %d, esperaba 2", antes)
	}

	sesiones, err := env.authRepo.ListActiveSessions(ctx, uno.User.ID, dos.Tokens.AccessJTI)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	var otra string
	for _, s := range sesiones {
		if !s.Current {
			otra = s.ID
			break
		}
	}
	if otra == "" {
		t.Fatal("no se encontro la otra sesion")
	}

	found, err := env.authRepo.RevokeSessionByID(ctx, uno.User.ID, otra)
	if err != nil || !found {
		t.Fatalf("RevokeSessionByID: found=%v err=%v", found, err)
	}

	// Queda una sesion y UNA familia: la del dispositivo cerrado murio con el.
	sesiones, err = env.authRepo.ListActiveSessions(ctx, uno.User.ID, dos.Tokens.AccessJTI)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(sesiones) != 1 || !sesiones[0].Current {
		t.Fatalf("tras cerrar una: %d sesiones, quedaba la actual? %v", len(sesiones), sesiones)
	}
	if vivos := refreshVivos(t, env, uno.User.ID); vivos != 1 {
		t.Fatalf("familias vivas = %d, esperaba 1: el dispositivo cerrado podria renovar", vivos)
	}

	// Repetir es inofensivo y no encuentra nada.
	if found, err := env.authRepo.RevokeSessionByID(ctx, uno.User.ID, otra); err != nil || found {
		t.Fatalf("segundo cierre: found=%v err=%v, esperaba false", found, err)
	}
}

// El id de la sesion no alcanza: tiene que ser de la cuenta que pide. Sin esto,
// conocer un id ajeno bastaria para sacar a otra persona de su cuenta.
func TestRevokeSessionByID_NoCierraSesionesDeOtraCuenta(t *testing.T) {
	env := armarEntornoBloqueo(t)
	ctx := context.Background()
	victima := registerTestUser(t, env.svc)

	sesiones, err := env.authRepo.ListActiveSessions(ctx, victima.User.ID, "")
	if err != nil || len(sesiones) == 0 {
		t.Fatalf("preparacion: %d sesiones, err=%v", len(sesiones), err)
	}

	ajeno := "00000000-0000-0000-0000-0000000000ff"
	found, err := env.authRepo.RevokeSessionByID(ctx, ajeno, sesiones[0].ID)
	if err != nil {
		t.Fatalf("RevokeSessionByID: %v", err)
	}
	if found {
		t.Fatal("se cerro la sesion de otra cuenta")
	}
	quedan, err := env.authRepo.ListActiveSessions(ctx, victima.User.ID, "")
	if err != nil || len(quedan) != len(sesiones) {
		t.Fatalf("la sesion ajena se toco igual: %d -> %d", len(sesiones), len(quedan))
	}
}

func TestRevokeAllSessions_ConYSinExcepcion(t *testing.T) {
	env := armarEntornoBloqueo(t)
	ctx := context.Background()
	uno := registerTestUser(t, env.svc)
	entrar(t, env)
	actual := entrar(t, env)

	// "Cerrar los demas": queda viva la actual, y su familia intacta — si se
	// revocara, esa sesion moriria al primer refresh y cerraria todo.
	n, err := env.authRepo.RevokeAllSessions(ctx, uno.User.ID, actual.Tokens.AccessJTI)
	if err != nil {
		t.Fatalf("RevokeAllSessions(except): %v", err)
	}
	if n != 2 {
		t.Fatalf("cerradas = %d, esperaba 2", n)
	}
	sesiones, err := env.authRepo.ListActiveSessions(ctx, uno.User.ID, actual.Tokens.AccessJTI)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(sesiones) != 1 || !sesiones[0].Current {
		t.Fatalf("deberia quedar solo la actual: %+v", sesiones)
	}
	if vivos := refreshVivos(t, env, uno.User.ID); vivos != 1 {
		t.Fatalf("familias vivas = %d, esperaba 1 (la de la sesion que sigue abierta)", vivos)
	}

	// Sin excepcion: no queda ninguna.
	n, err = env.authRepo.RevokeAllSessions(ctx, uno.User.ID, "")
	if err != nil {
		t.Fatalf("RevokeAllSessions(todas): %v", err)
	}
	if n != 1 {
		t.Fatalf("cerradas = %d, esperaba 1", n)
	}
	sesiones, err = env.authRepo.ListActiveSessions(ctx, uno.User.ID, "")
	if err != nil || len(sesiones) != 0 {
		t.Fatalf("quedaron %d sesiones abiertas, err=%v", len(sesiones), err)
	}
	if vivos := refreshVivos(t, env, uno.User.ID); vivos != 0 {
		t.Fatalf("familias vivas = %d, esperaba 0", vivos)
	}
}

// EL DEFECTO QUE ESTO CIERRA: cada rotacion de token insertaba una fila NUEVA
// de sesion y no revocaba la anterior. Con un token de acceso de quince
// minutos, un telefono en uso acumulaba una sesion "activa" cada cuarto de
// hora durante toda la vida del refresh — siete dias. La pantalla mostraba el
// mismo aparato repetido decenas de veces, con una sola marcada como actual.
//
// Y cerrar una de esas filas era peor que inutil: todas comparten familia de
// refresh, y cerrar revoca la familia entera. El usuario mataba su PROPIA
// sesion creyendo que cerraba la de un extrano.
//
// Sin el arreglo esta prueba falla: hay dos sesiones donde deberia haber una.
func TestRefresh_NoDuplicaLaSesionDelMismoDispositivo(t *testing.T) {
	env := armarEntornoBloqueo(t)
	ctx := context.Background()
	sesion := registerTestUser(t, env.svc)

	antes, err := env.authRepo.ListActiveSessions(ctx, sesion.User.ID, sesion.Tokens.AccessJTI)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(antes) != 1 {
		t.Fatalf("sesiones tras el registro = %d, esperaba 1", len(antes))
	}

	// Tres rotaciones seguidas, como haria un telefono a lo largo de una hora.
	tokens := sesion.Tokens
	for i := 0; i < 3; i++ {
		nuevos, err := env.svc.Refresh(ctx, tokens.RefreshToken, auth.LoginContext{
			IPAddress: "10.0.0.1", UserAgent: "Pruebas",
		})
		if err != nil {
			t.Fatalf("rotacion %d: %v", i+1, err)
		}
		tokens = nuevos
	}

	despues, err := env.authRepo.ListActiveSessions(ctx, sesion.User.ID, tokens.AccessJTI)
	if err != nil {
		t.Fatalf("ListActiveSessions tras rotar: %v", err)
	}
	if len(despues) != 1 {
		t.Fatalf("sesiones tras tres rotaciones = %d, esperaba 1: el mismo dispositivo no puede aparecer repetido", len(despues))
	}
	// Y la fila que queda es la del dispositivo actual, con su hora de entrada
	// original: la pantalla dice cuando entro, no cuando renovo.
	if !despues[0].Current {
		t.Error("la sesion que queda no esta marcada como la actual")
	}
	if despues[0].ID != antes[0].ID {
		t.Error("la rotacion cambio la identidad de la sesion en vez de moverla")
	}
	if !despues[0].CreatedAt.Equal(antes[0].CreatedAt) {
		t.Error("la rotacion movio la hora de entrada del dispositivo")
	}
	// El vencimiento SI avanza: la sesion vive lo que su refresh mas nuevo.
	if !despues[0].ExpiresAt.After(antes[0].ExpiresAt) {
		t.Error("el vencimiento de la sesion no avanzo con la rotacion")
	}
}

// Y cerrar la sesion de OTRO dispositivo no puede tumbar la propia. Antes, con
// las filas duplicadas, cualquiera de las viejas compartia familia con la viva.
func TestRevokeSessionByID_TrasRotarNoMataLaSesionPropia(t *testing.T) {
	env := armarEntornoBloqueo(t)
	ctx := context.Background()
	propia := registerTestUser(t, env.svc)
	otra := entrar(t, env)

	// La propia rota varias veces, como un telefono en uso.
	tokens := propia.Tokens
	for i := 0; i < 3; i++ {
		nuevos, err := env.svc.Refresh(ctx, tokens.RefreshToken, auth.LoginContext{})
		if err != nil {
			t.Fatalf("rotacion %d: %v", i+1, err)
		}
		tokens = nuevos
	}

	sesiones, err := env.authRepo.ListActiveSessions(ctx, propia.User.ID, tokens.AccessJTI)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	// Se cierra la que NO es la actual: la del otro dispositivo.
	var ajena string
	for _, s := range sesiones {
		if !s.Current {
			ajena = s.ID
			break
		}
	}
	if ajena == "" {
		t.Fatal("no se encontro una sesion distinta de la propia")
	}
	if _, err := env.authRepo.RevokeSessionByID(ctx, propia.User.ID, ajena); err != nil {
		t.Fatalf("RevokeSessionByID: %v", err)
	}

	// La propia sigue viva: puede renovar.
	if _, err := env.svc.Refresh(ctx, tokens.RefreshToken, auth.LoginContext{}); err != nil {
		t.Fatalf("cerrar la sesion ajena dejo fuera a la propia: %v", err)
	}
	// Y la ajena no.
	if _, err := env.svc.Refresh(ctx, otra.Tokens.RefreshToken, auth.LoginContext{}); err == nil {
		t.Fatal("la sesion cerrada pudo renovar")
	}
}
