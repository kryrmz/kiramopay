import { HttpMarketplaceRepository } from '../marketplace.http';
import { HttpCryptoRepository } from '../crypto.http';
import type { HttpClient } from '../client';

// Estos adaptadores REEMPLAZABAN el codigo de error del servidor por uno
// generico, asi que el motivo real nunca llegaba a la pantalla: el usuario veia
// "no se pudo comprar" sin saber por que. Se corrigio, pero nada lo probaba —
// las vistas mockean el adaptador, asi que revertir el arreglo dejaba la suite
// entera en verde. Estas pruebas son lo que hace que el arreglo se quede.
//
// Los codigos que importan: SIN_INTEGRACION (el cobro se rechaza porque no hay
// convenio con el socio) y PRICE_STALE (el precio de cripto esta vencido y no
// se ejecuta la orden contra un numero muerto).
function clienteQueFalla(code: string, message = 'del servidor'): HttpClient {
  const fallo = async () => ({ success: false, error: { code, message } });
  return { get: fallo, post: fallo, put: fallo, patch: fallo, del: fallo } as unknown as HttpClient;
}

describe('los adaptadores conservan el codigo de error del servidor', () => {
  describe('marketplace', () => {
    const casos: Array<[string, (r: HttpMarketplaceRepository) => Promise<{ error?: { code: string } }>]> = [
      ['createRide', (r) => r.createRide({ pickup: 'a', dropoff: 'b' } as never)],
      ['confirmRide', (r) => r.confirmRide('ride-1')],
      ['createFoodOrder', (r) => r.createFoodOrder({ restaurantId: 'r1', items: [] } as never)],
    ];

    it.each(casos)('%s deja pasar SIN_INTEGRACION', async (_nombre, llamar) => {
      const repo = new HttpMarketplaceRepository(clienteQueFalla('SIN_INTEGRACION'));
      const res = await llamar(repo);
      expect(res.error?.code).toBe('SIN_INTEGRACION');
    });

    it.each(casos)('%s cae a su codigo propio cuando el servidor no manda ninguno', async (_n, llamar) => {
      const sinCodigo = async () => ({ success: false, error: { message: 'boom' } });
      const repo = new HttpMarketplaceRepository(
        { get: sinCodigo, post: sinCodigo, put: sinCodigo, patch: sinCodigo, del: sinCodigo } as unknown as HttpClient,
      );
      const res = await llamar(repo);
      // Cualquiera de los genericos sirve; lo que no puede es quedar vacio.
      expect(res.error?.code).toBeTruthy();
    });
  });

  describe('cripto', () => {
    const casos: Array<[string, (r: HttpCryptoRepository) => Promise<{ error?: { code: string } }>]> = [
      ['buy', (r) => r.buy({ asset: 'BTC', fromAmount: 1000, fromCurrency: 'CRC' } as never)],
      ['sell', (r) => r.sell({ asset: 'BTC', amount: 0.01, toCurrency: 'CRC' } as never)],
      ['convert', (r) => r.convert({ fromAsset: 'BTC', toAsset: 'ETH', amount: 0.01 } as never)],
    ];

    it.each(casos)('%s deja pasar PRICE_STALE', async (_nombre, llamar) => {
      const repo = new HttpCryptoRepository(clienteQueFalla('PRICE_STALE'));
      const res = await llamar(repo);
      expect(res.error?.code).toBe('PRICE_STALE');
    });

    it.each(casos)('%s deja pasar MFA_REQUIRED', async (_nombre, llamar) => {
      const repo = new HttpCryptoRepository(clienteQueFalla('MFA_REQUIRED'));
      const res = await llamar(repo);
      expect(res.error?.code).toBe('MFA_REQUIRED');
    });
  });
});
