import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { LanguageProvider } from '@/i18n/LanguageContext';
import { ProfileView } from '../ProfileView';

// Los limites de transaccion dependen del nivel de KYC. Si la consulta fallaba,
// la pantalla caia a 500.000 diarios y 5.000.000 mensuales, que son los del
// nivel VERIFICADO: a una cuenta basica -cuyo tope real es 100.000 al dia- se
// le mostraba cinco veces su limite. Es el mismo error que la migracion 042
// tuvo que corregir en la base de datos.
const mocks = vi.hoisted(() => ({ getStatus: vi.fn() }));

vi.mock('@/api', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  getApiLayer: () => ({
    kyc: { getStatus: mocks.getStatus, verifyIdentity: vi.fn() },
    loyalty: { getReferralSummary: vi.fn().mockResolvedValue({ success: false }) },
    // La vista consulta el estado del segundo factor al montarse; sin esto la
    // promesa queda sin manejar y ensucia la corrida entera.
    mfa: { totpStatus: vi.fn().mockResolvedValue({ success: false }) },
  }),
}));

vi.mock('@/hooks/useApp', () => ({
  useApp: () => ({
    state: {
      accounts: [{ ccy: 'CRC', symbol: '₡', balance: 0, rateToUsd: 0.0019 }],
      baseCurrency: 'CRC',
      user: { id: 'u1', firstName: 'Ana', lastName: 'Mora', kycLevel: 0, email: 'a@b.co' },
      settings: { biometricEnabled: false, notifications: true, language: 'es' },
      transactions: [],
      theme: 'light',
    },
    dispatch: vi.fn(),
  }),
}));

// La fila que muestra el limite, buscada por su etiqueta DENTRO del arbol que
// esta prueba acaba de pintar. Dos motivos: se afirma sobre el VALOR y no sobre
// un caracter suelto que puede venir de cualquier otra parte de la pantalla —el
// bloque de referidos pinta un guion cuando su consulta falla—, y acotando al
// contenedor no se lee por error el arbol de otra prueba.
const textoDeLaFilaDelLimite = (contenedor: HTMLElement) =>
  within(contenedor).getAllByText(/Límite diario/)[0]?.textContent;

const pintar = () =>
  render(
    <LanguageProvider>
      <ProfileView />
    </LanguageProvider>,
  );

describe('ProfileView: limites de transaccion', () => {
  beforeEach(() => {
    // El resto de la suite lo fija; sin esto el idioma se carga de forma
    // asincronica y la fila aparece primero en ingles, lo que hacia que la
    // asercion dependiera del momento en que corriera.
    localStorage.setItem('kiramopay_language', 'es');
    mocks.getStatus.mockReset();
  });
  // Desmontar el arbol al terminar cada prueba. Sin esto quedan dos pantallas
  // montadas a la vez, con sus efectos vivos, y la segunda no llega a pintar.
  afterEach(() => {
    cleanup();
  });

  it('si no se pudieron consultar, no inventa el limite del nivel verificado', async () => {
    mocks.getStatus.mockResolvedValue({ success: false, error: { code: 'X', message: 'sin red' } });
    const { container } = pintar();

    // 500.000 es el tope del nivel VERIFICADO; una cuenta basica tiene 100.000.
    await waitFor(() => expect(screen.queryByText(/₡500,000/)).toBeNull());
    // La asercion va sobre LA FILA DEL LIMITE, no sobre el caracter suelto: hay
    // otros guiones en la pantalla —el bloque de referidos pinta uno cuando su
    // consulta falla, que es justo lo que hace este mock—, asi que buscar '—' a
    // secas pasaba sin probar nada de los limites.
    await waitFor(() =>
      expect(textoDeLaFilaDelLimite(container)).toBe('Límite diario: —'),
    );
  });

  it('con la respuesta del servidor muestra el limite real de la cuenta', async () => {
    mocks.getStatus.mockResolvedValue({
      success: true,
      data: { kycLevel: 0, kycStatus: 'pending', dailyLimit: 100000, monthlyLimit: 500000 },
    });
    const { container } = pintar();

    await waitFor(() => expect(textoDeLaFilaDelLimite(container)).toBe('Límite diario: ₡100,000.00'));
  });
});
