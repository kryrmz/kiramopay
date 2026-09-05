package transaction

import (
	"testing"

	"github.com/kiramopay/backend/internal/kyc"
	"github.com/kiramopay/backend/internal/wallet"
)

// EL AGUJERO QUE ESTO CIERRA: el tope diario esta en centimos de COLON
// (10.000.000 = 100.000 colones para una cuenta basica) y se comparaba contra
// el monto viniera en la moneda que viniera. En dolares no frenaba nada: USD
// 5.000 son 500.000 centimos, muy por debajo de 10.000.000, asi que una
// billetera en dolares podia mover unas 26 veces su tope. Aplicaba a las
// transferencias y, por lo tanto, tambien al escrow que acababa de empezar a
// consultar ese mismo tope.
//
// Sin el arreglo, topeDiarioDe no existe y el llamante pasaba siempre
// w.DailyLimit.
func TestTopeDiarioDe_EligeElTopeDeLaMoneda(t *testing.T) {
	w := &wallet.WalletRecord{DailyLimit: 10_000_000, DailyLimitUSD: 19_000}

	if tope, ok := topeDiarioDe(w, "CRC"); !ok || tope != 10_000_000 {
		t.Errorf("CRC = %d (ok=%v), esperaba 10000000", tope, ok)
	}
	if tope, ok := topeDiarioDe(w, "USD"); !ok || tope != 19_000 {
		t.Errorf("USD = %d (ok=%v), esperaba 19000", tope, ok)
	}
	// Insensible a mayusculas, como el resto del codigo de monedas.
	if tope, ok := topeDiarioDe(w, "usd"); !ok || tope != 19_000 {
		t.Errorf("usd = %d (ok=%v), esperaba 19000", tope, ok)
	}
	// El caso que importa: el tope en dolares NO puede ser el de colones.
	if crc, _ := topeDiarioDe(w, "CRC"); crc == 19_000 {
		t.Error("el tope en colones es el de dolares")
	}
}

// Una moneda sin tope definido no puede salir "sin tope": seria el mismo
// agujero con otro nombre.
func TestTopeDiarioDe_UnaMonedaDesconocidaNoQuedaSinTope(t *testing.T) {
	w := &wallet.WalletRecord{DailyLimit: 10_000_000, DailyLimitUSD: 19_000}
	for _, moneda := range []string{"GTQ", "PAB", "EUR", ""} {
		if _, ok := topeDiarioDe(w, moneda); ok {
			t.Errorf("la moneda %q se reporta con tope conocido", moneda)
		}
	}
}

// Los tramos por nivel de KYC tienen que existir en LAS DOS monedas y crecer
// juntos: un nivel superior no puede quedar con menos margen que uno inferior.
func TestLevelLimits_TieneTramosEnLasDosMonedas(t *testing.T) {
	niveles := []int{kyc.LevelBasic, kyc.LevelVerified, kyc.LevelComplete}
	var previoCRC, previoUSD int64
	for _, n := range niveles {
		lim := kyc.LevelLimits[n]
		if lim.DailyMinor <= 0 || lim.DailyMinorUSD <= 0 {
			t.Fatalf("nivel %d sin tope diario en alguna moneda: CRC=%d USD=%d", n, lim.DailyMinor, lim.DailyMinorUSD)
		}
		if lim.MonthlyMinor <= 0 || lim.MonthlyMinorUSD <= 0 {
			t.Fatalf("nivel %d sin tope mensual en alguna moneda", n)
		}
		if lim.DailyMinor <= previoCRC || lim.DailyMinorUSD <= previoUSD {
			t.Errorf("nivel %d no amplia el margen respecto al anterior", n)
		}
		// El tope diario no puede superar al mensual.
		if lim.DailyMinor > lim.MonthlyMinor || lim.DailyMinorUSD > lim.MonthlyMinorUSD {
			t.Errorf("nivel %d tiene un tope diario mayor que el mensual", n)
		}
		previoCRC, previoUSD = lim.DailyMinor, lim.DailyMinorUSD
	}
}
