package appversion

import (
	"strings"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Handler apuntado a servidores de prueba en vez de a GitHub.
func handlerDePrueba(api, web string) *Handler {
	h := NewHandler()
	h.apiURL = api
	h.webURL = web
	h.descargaFmt = web + "/download/%s/kiramopay.apk"
	h.token = ""
	return h
}

func pedir(t *testing.T, h *Handler) (int, infoVersion) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.GetLatest(rec, httptest.NewRequest(http.MethodGet, "/api/v1/app/version", nil))
	var sobre struct {
		Success bool        `json:"success"`
		Data    infoVersion `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sobre); err != nil {
		t.Fatalf("respuesta no es JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return rec.Code, sobre.Data
}

// Servidor que imita la API de releases de GitHub.
func servidorAPI(t *testing.T, status int, cuotaAgotada bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cuotaAgotada {
			w.Header().Set("X-RateLimit-Remaining", "0")
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v2.3.6","assets":[
			{"name":"KiramoPay-unsigned.ipa","browser_download_url":"https://ejemplo/ipa"},
			{"name":"kiramopay.apk","browser_download_url":"https://ejemplo/apk"}]}`))
	}))
}

// Servidor que imita github.com/<repo>/releases/latest: redirige al tag.
func servidorWeb(t *testing.T, redirige bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !redirige {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", "https://github.com/keylormr/kiramopay/releases/tag/v2.3.6")
		w.WriteHeader(http.StatusFound)
	}))
}

// La release lleva el .ipa de iOS ademas del APK: hay que elegir el .apk, no
// el primero de la lista.
func TestGetLatest_APIEligeElAPKNoElPrimerAdjunto(t *testing.T) {
	api := servidorAPI(t, http.StatusOK, false)
	defer api.Close()
	web := servidorWeb(t, true)
	defer web.Close()

	code, info := pedir(t, handlerDePrueba(api.URL, web.URL))
	if code != http.StatusOK || info.Version != "2.3.6" || info.URL != "https://ejemplo/apk" {
		t.Fatalf("code=%d info=%+v, esperaba 200 con la 2.3.6 y la URL del apk", code, info)
	}
}

// El caso real que tumbo el aviso de actualizacion: la cuota de la API de
// GitHub esta agotada para la IP compartida de Render. El camino web tiene que
// salvarlo sin que el usuario note nada.
func TestGetLatest_CuotaDeLaAPIAgotadaCaeALaRedireccion(t *testing.T) {
	api := servidorAPI(t, http.StatusForbidden, true)
	defer api.Close()
	web := servidorWeb(t, true)
	defer web.Close()

	code, info := pedir(t, handlerDePrueba(api.URL, web.URL))
	if code != http.StatusOK {
		t.Fatalf("code=%d, esperaba 200 por el camino web", code)
	}
	if info.Version != "2.3.6" {
		t.Fatalf("version=%q, esperaba 2.3.6 sacada del tag de la redireccion", info.Version)
	}
	if want := web.URL + "/download/v2.3.6/kiramopay.apk"; info.URL != want {
		t.Fatalf("url=%q, esperaba %q", info.URL, want)
	}
}

func TestGetLatest_LosDosCaminosCaidosSinCacheDa503(t *testing.T) {
	api := servidorAPI(t, http.StatusForbidden, true)
	defer api.Close()
	web := servidorWeb(t, false)
	defer web.Close()

	code, _ := pedir(t, handlerDePrueba(api.URL, web.URL))
	if code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d, esperaba 503 sin cache", code)
	}
}

// Una cache vencida sigue siendo mejor que nada: la app ofrece la version que
// se conocia en vez de no ofrecer ninguna.
func TestGetLatest_CacheViejaSalvaCuandoTodoFalla(t *testing.T) {
	api := servidorAPI(t, http.StatusForbidden, true)
	defer api.Close()
	web := servidorWeb(t, false)
	defer web.Close()

	h := handlerDePrueba(api.URL, web.URL)
	h.cache = &infoVersion{Version: "2.3.5", URL: "https://ejemplo/viejo.apk"}
	h.cachedAt = time.Now().Add(-time.Hour)

	code, info := pedir(t, h)
	if code != http.StatusOK || info.Version != "2.3.5" {
		t.Fatalf("code=%d info=%+v, esperaba la cache vieja", code, info)
	}
}

// La cache fresca no vuelve a salir a la red.
func TestGetLatest_CacheFrescaNoConsultaAGitHub(t *testing.T) {
	llamadas := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { llamadas++ }))
	defer api.Close()
	web := servidorWeb(t, true)
	defer web.Close()

	h := handlerDePrueba(api.URL, web.URL)
	h.cache = &infoVersion{Version: "2.3.6", URL: "https://ejemplo/apk"}
	h.cachedAt = time.Now()

	if code, _ := pedir(t, h); code != http.StatusOK {
		t.Fatalf("code=%d, esperaba 200 desde la cache", code)
	}
	if llamadas != 0 {
		t.Fatalf("consulto a GitHub %d veces teniendo cache fresca", llamadas)
	}
}

// Con token configurado, la peticion a la API lo lleva: es lo que sube el
// limite de 60 a 5000 por hora.
func TestGetLatest_ConTokenLoMandaEnLaCabecera(t *testing.T) {
	recibida := make(chan string, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case recibida <- r.Header.Get("Authorization"):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v2.3.6","assets":[{"name":"kiramopay.apk","browser_download_url":"https://ejemplo/apk"}]}`))
	}))
	defer api.Close()
	web := servidorWeb(t, true)
	defer web.Close()

	h := handlerDePrueba(api.URL, web.URL)
	h.token = "ghp_secreto"
	if code, _ := pedir(t, h); code != http.StatusOK {
		t.Fatalf("code=%d", code)
	}
	if got := <-recibida; got != "Bearer ghp_secreto" {
		t.Fatalf("Authorization = %q", got)
	}
}

// ── Reparto por plataforma ───────────────────────────────────────────────────
// Android e iOS comparten la version pero no la URL: iOS no puede instalar un
// binario bajado de un link.

func conCacheYCanal(iosURL string) *Handler {
	h := NewHandler()
	h.iosUpdateURL = iosURL
	h.cache = &infoVersion{Version: "2.3.6", URL: "https://ejemplo/kiramopay.apk"}
	h.cachedAt = time.Now()
	return h
}

func pedirPlataforma(t *testing.T, h *Handler, query string) (int, infoVersion) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.GetLatest(rec, httptest.NewRequest(http.MethodGet, "/api/v1/app/version"+query, nil))
	var sobre struct {
		Data infoVersion `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sobre)
	return rec.Code, sobre.Data
}

// Los APK ya instalados llaman sin ?platform= y tienen que seguir recibiendo la
// URL del .apk. Romper esto deja sin actualizaciones al parque Android entero.
func TestPlataforma_SinParametroSigueSiendoAndroid(t *testing.T) {
	code, info := pedirPlataforma(t, conCacheYCanal(""), "")
	if code != http.StatusOK || info.URL != "https://ejemplo/kiramopay.apk" {
		t.Fatalf("code=%d info=%+v, esperaba la URL del apk", code, info)
	}
}

func TestPlataforma_IOSDevuelveSuCanalYLaMismaVersion(t *testing.T) {
	const canal = "https://testflight.apple.com/join/abc123"
	code, info := pedirPlataforma(t, conCacheYCanal(canal), "?platform=ios")
	if code != http.StatusOK {
		t.Fatalf("code=%d, esperaba 200", code)
	}
	if info.URL != canal {
		t.Errorf("url=%q, esperaba el canal iOS %q", info.URL, canal)
	}
	if info.Version != "2.3.6" {
		t.Errorf("version=%q, esperaba la misma que Android (2.3.6)", info.Version)
	}
}

// Sin canal configurado no hay a donde mandar al usuario: 503 y la app calla,
// que es mejor que abrir una hoja con un boton que no lleva a ningun lado.
func TestPlataforma_IOSSinCanalNoOfrece(t *testing.T) {
	if code, _ := pedirPlataforma(t, conCacheYCanal(""), "?platform=ios"); code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d, esperaba 503", code)
	}
}

func TestPlataforma_InvalidaEs400(t *testing.T) {
	if code, _ := pedirPlataforma(t, conCacheYCanal("https://x.test"), "?platform=windows"); code != http.StatusBadRequest {
		t.Fatalf("code=%d, esperaba 400", code)
	}
}

func TestPlataforma_ToleraMayusculasYEspacios(t *testing.T) {
	code, info := pedirPlataforma(t, conCacheYCanal("https://testflight.apple.com/join/abc"), "?platform=%20iOS%20")
	if code != http.StatusOK || info.URL == "" {
		t.Fatalf("code=%d info=%+v, esperaba resolver iOS igual", code, info)
	}
}

// EL DEFECTO QUE ESTO CIERRA: con GitHub caido y la cache vencida, la respuesta
// salia TAL CUAL de la cache — y la cache siempre guarda la variante de Android.
// Un cliente iOS recibia la URL del .apk, un archivo que en iOS no se puede
// instalar. Es justo la confusion que la respuesta por plataforma vino a evitar,
// y aparecia solo en el momento en que mas molesta: cuando GitHub no responde.
//
// Sin el arreglo esta prueba falla: la URL devuelta termina en .apk.
func TestGetLatest_ConCacheViejaIOSNoRecibeElAPK(t *testing.T) {
	api := servidorAPI(t, http.StatusForbidden, true)
	defer api.Close()
	web := servidorWeb(t, false)
	defer web.Close()

	h := handlerDePrueba(api.URL, web.URL)
	h.iosUpdateURL = "https://apps.apple.com/app/kiramopay"
	h.cache = &infoVersion{Version: "2.3.5", URL: "https://ejemplo/viejo.apk"}
	h.cachedAt = time.Now().Add(-time.Hour)

	code, info := pedirPlataforma(t, h, "?platform=ios")
	if code != http.StatusOK {
		t.Fatalf("code=%d, esperaba 200 desde la cache vieja", code)
	}
	if info.Version != "2.3.5" {
		t.Fatalf("version=%q, esperaba la de la cache", info.Version)
	}
	if strings.HasSuffix(info.URL, ".apk") {
		t.Fatalf("un cliente iOS recibio la URL del APK: %q", info.URL)
	}
	if info.URL != h.iosUpdateURL {
		t.Fatalf("url=%q, esperaba el canal de iOS", info.URL)
	}
}

// Y android sigue recibiendo el .apk de la cache, que es lo correcto para el.
func TestGetLatest_ConCacheViejaAndroidSiRecibeElAPK(t *testing.T) {
	api := servidorAPI(t, http.StatusForbidden, true)
	defer api.Close()
	web := servidorWeb(t, false)
	defer web.Close()

	h := handlerDePrueba(api.URL, web.URL)
	h.iosUpdateURL = "https://apps.apple.com/app/kiramopay"
	h.cache = &infoVersion{Version: "2.3.5", URL: "https://ejemplo/viejo.apk"}
	h.cachedAt = time.Now().Add(-time.Hour)

	_, info := pedirPlataforma(t, h, "?platform=android")
	if !strings.HasSuffix(info.URL, ".apk") {
		t.Fatalf("android no recibio el APK: %q", info.URL)
	}
}
