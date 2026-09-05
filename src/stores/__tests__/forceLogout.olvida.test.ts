import { useAuthStore } from '../auth.store';
import { CLAVE_ULTIMO_IDENTIFICADOR, CLAVE_ULTIMO_NOMBRE } from '../olvidarUltimoAcceso';

// Un cierre de sesion FORZADO no es lo mismo que uno normal: la cuenta perdio
// el acceso (la bloquearon, o la sesion se revoco). La tarjeta de acceso rapido
// y la credencial del llavero ya no sirven para entrar, asi que dejarlas solo
// deja el nombre de esa persona a la vista y una contrasena guardada sin
// proposito. Es la regla del proyecto: quitar el acceso no borra registros,
// pero la credencial SI se destruye.
const mocks = vi.hoisted(() => ({ deleteCredentials: vi.fn().mockResolvedValue(true) }));

vi.mock('@/services/biometric', () => ({
  biometricService: { deleteCredentials: mocks.deleteCredentials },
}));
vi.mock('@/services/dataSync', () => ({ syncAllData: vi.fn().mockResolvedValue(undefined) }));

describe('forceLogout', () => {
  beforeEach(() => {
    localStorage.clear();
    mocks.deleteCredentials.mockClear();
    localStorage.setItem(CLAVE_ULTIMO_IDENTIFICADOR, 'keilor');
    localStorage.setItem(CLAVE_ULTIMO_NOMBRE, 'Keilor Martinez');
  });

  it('olvida al ultimo usuario cuando la cuenta pierde el acceso', () => {
    useAuthStore.getState().forceLogout('blocked');

    expect(localStorage.getItem(CLAVE_ULTIMO_IDENTIFICADOR)).toBeNull();
    expect(localStorage.getItem(CLAVE_ULTIMO_NOMBRE)).toBeNull();
    expect(mocks.deleteCredentials).toHaveBeenCalledWith('kiramopay');
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    // El motivo se conserva: la pantalla de login lo muestra.
    expect(useAuthStore.getState().logoutReason).toBe('blocked');
  });

  // EL CASO QUE FALTABA, y que es el que de verdad ocurre a diario: forceLogout
  // es TAMBIEN el manejador generico de 401 cuyo refresco falla, y el servidor
  // corta por inactividad a los 30 minutos. Sin condicionarlo al motivo, dejar
  // la aplicacion en segundo plano media hora borraba la tarjeta de acceso
  // rapido y la credencial de la huella. Una sesion que vence no es una cuenta
  // revocada.
  it('una sesion vencida NO borra el acceso rapido', () => {
    useAuthStore.getState().forceLogout();

    expect(localStorage.getItem(CLAVE_ULTIMO_IDENTIFICADOR)).toBe('keilor');
    expect(localStorage.getItem(CLAVE_ULTIMO_NOMBRE)).toBe('Keilor Martinez');
    expect(mocks.deleteCredentials).not.toHaveBeenCalled();
    // Pero la sesion si termina.
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  // Y un cierre de sesion NORMAL conserva el acceso rapido: es justo lo que el
  // usuario espera encontrar la proxima vez que abre la aplicacion.
  it('un cierre de sesion normal conserva el acceso rapido', () => {
    useAuthStore.getState().logout();

    expect(localStorage.getItem(CLAVE_ULTIMO_IDENTIFICADOR)).toBe('keilor');
    expect(localStorage.getItem(CLAVE_ULTIMO_NOMBRE)).toBe('Keilor Martinez');
    expect(mocks.deleteCredentials).not.toHaveBeenCalled();
  });
});
