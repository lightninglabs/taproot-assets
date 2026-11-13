package address

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// TestNewTransferFromFragmentRejectsOutputIndex asserts that a send fragment
// cannot name an output index beyond the transaction it references.
func TestNewTransferFromFragmentRejectsOutputIndex(t *testing.T) {
	t.Parallel()

	courier := RandProofCourierAddrForVersion(t, V2)
	addr, _, _ := RandAddrWithVersion(
		t, &RegressionNetTap, courier, V2,
	)

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Timestamp: time.Now()},
		Transactions: []*wire.MsgTx{tx},
	}

	fragment := &proof.SendFragment{
		Version:     proof.SendFragmentV1,
		BlockHeader: block.Header,
		BlockHeight: 100,
		OutPoint: wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 1,
		},
		Outputs: map[asset.ID]proof.SendOutput{
			{}: {Amount: 1},
		},
	}

	_, err := NewTransferFromFragment(addr, block, fragment, nil)
	require.ErrorContains(t, err, "out of range")
}
