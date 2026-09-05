// Package appversion expone la ultima version publicada del APK para que la
// app instalada detecte actualizaciones y ofrezca bajarlas en un toque, sin
// depender de una tienda.
//
// La fuente es el ultimo release de GitHub, por DOS caminos:
//
//  1. La API (api.github.com), que es autoritativa: da el nombre real de cada
//     archivo adjunto. Sin token su limite son 60 peticiones por hora POR IP, y
//     el backend sale por una IP COMPARTIDA de Render: la cuota se agota con lo
//     que hagan los demas inquilinos, no con lo nuestro. Eso tumbo el aviso de
//     actualizacion justo despues de publicar la 2.3.6 y los telefonos en 2.3.5
//     no se enteraron. Con GITHUB_TOKEN configurado el limite sube a 5000/hora.
//  2. La redireccion de github.com/<repo>/releases/latest, que NO pasa por la
//     API ni tiene ese limite: su cabecera Location trae el tag. Con el tag, la
//     URL del APK es deterministica porque el nombre lo fija nuestro propio CI.
//
// Se intenta la API primero y se cae al segundo camino; lo que funcione se
// cachea, para que mil telefonos no golpeen a GitHub.
//
// Las dos plataformas comparten la VERSION pero no la URL, porque no se
// actualizan igual:
//
//   - Android baja el .apk del release y el sistema lo instala encima (misma
//     firma, versionCode creciente). La URL sale del propio release.
//   - iOS no puede instalar un binario bajado de un link. Actualizar es siempre
//     mandar al usuario a su canal: TestFlight, App Store, o un manifiesto OTA
//     itms-services:// si la distribucion es Ad Hoc. Cual de los tres se
//     configura con IOS_UPDATE_URL; sin esa variable no hay canal y la app iOS
//     no ofrece nada, que es preferible a un boton que no lleva a ningun lado.
package appversion

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kiramopay/backend/pkg/response"
)

const (
	apiURL      = "https://api.github.com/repos/keylormr/kiramopay/releases/latest"
	webURL      = "https://github.com/keylormr/kiramopay/releases/latest"
	descargaFmt = "https://github.com/keylormr/kiramopay/releases/download/%s/kiramopay.apk"
	cacheTTL    = 10 * time.Minute
)

type infoVersion struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type Handler struct {
	mu       sync.Mutex
	cache    *infoVersion
	cachedAt time.Time
	client   *http.Client
	// Canal de actualizacion de iOS (IOS_UPDATE_URL). Vacio mientras no exista
	// distribucion iOS; ver el comentario del paquete.
	iosUpdateURL string
	// Inyectables para las pruebas; en produccion son las constantes de arriba.
	apiURL      string
	webURL      string
	descargaFmt string
	token       string
}

func NewHandler() *Handler {
	return &Handler{
		// Sin seguir redirecciones: el camino web necesita LEER el Location,
		// no ir a buscar la pagina HTML del release (que serian cientos de KB
		// por peticion para extraer un numero de version).
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		apiURL:      apiURL,
		webURL:      webURL,
		descargaFmt: descargaFmt,
		// Opcional: sube el limite de la API de 60 a 5000 por hora. Sin el, el
		// camino web hace el trabajo igual.
		token:        os.Getenv("GITHUB_TOKEN"),
		iosUpdateURL: strings.TrimSpace(os.Getenv("IOS_UPDATE_URL")),
	}
}

// GetLatest responde {version, url} del ultimo APK publicado. Publico: la app
// lo consulta ANTES de saber si hay sesion. Si los dos caminos fallan y no hay
// cache, devuelve 503 y la app simplemente no ofrece actualizar esta vez.
func (h *Handler) GetLatest(w http.ResponseWriter, r *http.Request) {
	// Sin parametro se asume android: los APK ya instalados llaman a este
	// endpoint sin plataforma y tienen que seguir recibiendo la URL del .apk.
	plataforma := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("platform")))
	if plataforma == "" {
		plataforma = "android"
	}
	if plataforma != "android" && plataforma != "ios" {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "platform must be android or ios")
		return
	}
	// iOS sin canal configurado: no es un fallo del servicio, es que todavia no
	// hay por donde actualizar. Se responde 503, que es lo que la app ya sabe
	// tolerar en silencio.
	if plataforma == "ios" && h.iosUpdateURL == "" {
		response.Error(w, http.StatusServiceUnavailable, "VERSION_UNAVAILABLE", "no ios update channel configured")
		return
	}

	h.mu.Lock()
	if h.cache != nil && time.Since(h.cachedAt) < cacheTTL {
		info := *h.cache
		h.mu.Unlock()
		response.JSON(w, http.StatusOK, h.paraPlataforma(info, plataforma))
		return
	}
	h.mu.Unlock()

	info, err := h.desdeAPI(r)
	if err != nil {
		slog.Warn("app version: la API de GitHub no sirvio, se prueba la redireccion web", "err", err)
		info, err = h.desdeRedireccion(r)
	}
	if err != nil {
		slog.Warn("app version: ningun camino a GitHub funciono", "err", err)
		h.responderCacheViejaOFallo(w, plataforma)
		return
	}

	h.mu.Lock()
	h.cache = info
	h.cachedAt = time.Now()
	h.mu.Unlock()
	response.JSON(w, http.StatusOK, h.paraPlataforma(*info, plataforma))
}

// paraPlataforma adapta la respuesta cacheada (que es la de Android, con la URL
// del .apk) a la plataforma que pregunta. La version es la misma en las dos:
// sale del tag del release.
func (h *Handler) paraPlataforma(info infoVersion, plataforma string) infoVersion {
	if plataforma == "ios" {
		return infoVersion{Version: info.Version, URL: h.iosUpdateURL}
	}
	return info
}

// desdeAPI lee el release por la API: es la fuente autoritativa del nombre del
// archivo adjunto (la release lleva tambien el .ipa de iOS, asi que hay que
// elegir el .apk, no el primero).
func (h *Handler) desdeAPI(r *http.Request) (*infoVersion, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 403 con la cuota agotada es el caso real en Render; se distingue en
		// el log porque la accion es distinta (configurar GITHUB_TOKEN).
		if resto := resp.Header.Get("X-RateLimit-Remaining"); resto == "0" {
			return nil, fmt.Errorf("cuota de la API de GitHub agotada para esta IP (status %d): configurar GITHUB_TOKEN", resp.StatusCode)
		}
		return nil, fmt.Errorf("la API de GitHub respondio %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	info := infoVersion{Version: strings.TrimPrefix(release.TagName, "v")}
	for _, a := range release.Assets {
		if strings.HasSuffix(a.Name, ".apk") {
			info.URL = a.BrowserDownloadURL
			break
		}
	}
	if info.Version == "" || info.URL == "" {
		return nil, fmt.Errorf("el release %q no trae un .apk", release.TagName)
	}
	return &info, nil
}

// desdeRedireccion saca el tag de la cabecera Location de la pagina de releases
// y arma la URL del APK. No pasa por la API, asi que no tiene su limite por IP.
func (h *Handler) desdeRedireccion(r *http.Request) (*infoVersion, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.webURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return nil, fmt.Errorf("releases/latest respondio %d, se esperaba una redireccion", resp.StatusCode)
	}
	destino := resp.Header.Get("Location")
	i := strings.LastIndex(destino, "/tag/")
	if i < 0 {
		return nil, fmt.Errorf("la redireccion no apunta a un tag: %q", destino)
	}
	tag := destino[i+len("/tag/"):]
	if tag == "" {
		return nil, fmt.Errorf("la redireccion no trae tag: %q", destino)
	}
	return &infoVersion{
		Version: strings.TrimPrefix(tag, "v"),
		URL:     fmt.Sprintf(h.descargaFmt, tag),
	}, nil
}

// Con GitHub caido, una cache vencida sigue siendo mejor que nada; sin cache,
// 503 honesto.
//
// Recibe la plataforma y adapta igual que los dos caminos de exito. Sin eso
// devolvia la cache TAL CUAL, y la cache siempre guarda la variante de Android:
// un cliente iOS con la cache vencida y GitHub caido recibia la URL del .apk,
// un archivo que en iOS no se puede instalar. Es justo la confusion que la
// respuesta por plataforma vino a evitar.
func (h *Handler) responderCacheViejaOFallo(w http.ResponseWriter, plataforma string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cache != nil {
		response.JSON(w, http.StatusOK, h.paraPlataforma(*h.cache, plataforma))
		return
	}
	response.Error(w, http.StatusServiceUnavailable, "VERSION_UNAVAILABLE", "version check failed")
}
