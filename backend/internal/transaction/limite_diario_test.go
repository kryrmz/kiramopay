package transaction

import (
	"strings"
	"testing"
)

// La lista de tipos de DailyOutgoingMinor es la definicion operativa de
// "salida de dinero". Un tipo saliente que no este ahi hace que el tope diario
// valga el doble: se gasta entero por ese camino y despues otra vez por los
// demas. Es lo que pasaba con escrow_fund.
//
// Esta prueba lee la consulta real, asi que no se puede quedar desactualizada
// respecto al codigo que ejecuta.
func TestDailyOutgoingMinor_CuentaTodosLosCaminosDeSalida(t *testing.T) {
	consulta := sqlSalidaDiaria

	salientes := []string{
		TypeSinpeSend, TypeQRPayment, TypeBillPayment, TypeRecharge,
		TypeWithdrawal, TypeP2PSend, TypeCryptoBuy,
		// El que faltaba: financiar un escrow saca dinero de la billetera del
		// comprador igual que una transferencia.
		"escrow_fund",
		// Y estos dos, que tambien debitan la billetera contra una contraparte
		// externa. Hoy ninguno opera en produccion, pero la lista describe lo
		// que ES una salida, no lo que esta encendido.
		"payout_sent", "marketplace",
	}
	for _, tipo := range salientes {
		if !strings.Contains(consulta, "'"+tipo+"'") {
			t.Errorf("el tipo saliente %q no cuenta para el tope diario: se podria gastar el tope por ese camino y otra vez por los demas", tipo)
		}
	}

	// Y los ENTRANTES no pueden estar: sumarlos haria que recibir dinero
	// consumiera el tope de gasto de quien lo recibe.
	entrantes := []string{
		TypeSinpeReceive, TypeQRReceive, TypeDeposit, TypeP2PReceive,
		TypeCryptoSell, "escrow_receive", "escrow_refund",
	}
	for _, tipo := range entrantes {
		if strings.Contains(consulta, "'"+tipo+"'") {
			t.Errorf("el tipo ENTRANTE %q cuenta para el tope de gasto: recibir dinero no gasta", tipo)
		}
	}
}
