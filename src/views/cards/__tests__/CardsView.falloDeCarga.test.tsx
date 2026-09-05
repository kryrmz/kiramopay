import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LanguageProvider } from '@/i18n/LanguageContext';
import { CardsView } from '../CardsView';

// Si la consulta de tarjetas fallaba, la pantalla pintaba el estado vacio
// -"todavia no tienes tarjetas"- con el boton de crear una. A alguien que SI
// tiene su tarjeta se le decia que no la tiene y se le invitaba a sacar otra.
const mocks = vi.hoisted(() => ({ getCards: vi.fn(), createCard: vi.fn(), freezeCard: vi.fn() }));

vi.mock('@/api', () => ({
  getApiLayer: () => ({
    cards: {
      getCards: mocks.getCards,
      createCard: mocks.createCard,
      freezeCard: mocks.freezeCard,
      updateLimits: vi.fn(),
      cancelCard: vi.fn(),
    },
  }),
}));

const pintar = () =>
  render(
    <LanguageProvider>
      <CardsView />
    </LanguageProvider>,
  );

describe('CardsView cuando no se pudo consultar', () => {
  beforeEach(() => {
    mocks.getCards.mockReset();
    mocks.createCard.mockReset();
    mocks.freezeCard.mockReset();
    mocks.freezeCard.mockResolvedValue({ success: true });
  });

  it('no ofrece crear una tarjeta: dice que no se pudo consultar', async () => {
    mocks.getCards.mockResolvedValue({ success: false, error: { code: 'X', message: 'sin red' } });
    pintar();

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /reintentar|retry/i })).toBeTruthy(),
    );
    // El boton de crear es justamente el que no debe estar.
    expect(screen.queryByRole('button', { name: /crear|create/i })).toBeNull();
    expect(mocks.createCard).not.toHaveBeenCalled();
  });

  // El fallo de congelar, cambiar limites o cancelar se escribia en `error`,
  // pero el unico sitio que lo pintaba estaba dentro del estado vacio — la rama
  // que NO se muestra cuando hay tarjeta. Es decir: justo las acciones que solo
  // existen teniendo una tarjeta fallaban en silencio.
  it('un fallo al congelar la tarjeta se muestra', async () => {
    const congelar = vi.fn().mockResolvedValue({
      success: false,
      error: { code: 'FREEZE_FAILED', message: 'No se pudo congelar la tarjeta' },
    });
    mocks.getCards.mockResolvedValue({
      success: true,
      data: [{
        id: 'c1', last4: '4242', brand: 'visa', status: 'active', type: 'virtual',
        currency: 'CRC', dailyLimit: 500, atmLimit: 100, monthlyLimit: 5000,
        cardholderName: 'Keilor Martinez', expiryMonth: 12, expiryYear: 2030,
      }],
    });
    mocks.freezeCard.mockImplementation(congelar);

    const user = userEvent.setup();
    pintar();

    const boton = await screen.findByRole('button', { name: /congelar|freeze/i });
    await user.click(boton);

    await waitFor(() =>
      expect(screen.getByText('No se pudo congelar la tarjeta')).toBeInTheDocument(),
    );
  });

  it('sin tarjetas de verdad si ofrece crear una', async () => {
    mocks.getCards.mockResolvedValue({ success: true, data: [] });
    pintar();

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /crear|create/i })).toBeTruthy(),
    );
    expect(screen.queryByRole('button', { name: /reintentar|retry/i })).toBeNull();
  });
});
