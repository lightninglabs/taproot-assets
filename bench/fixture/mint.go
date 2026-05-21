package fixture

import (
	"database/sql"
	"testing"

	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapnode/tapnodemock"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/stretchr/testify/require"
)

// Mint extends Storage with a running ChainPlanter wired to mock chain /
// wallet / key-ring / gen-signer. Sufficient for the mintrpc surface
// (MintAsset, FundBatch, SealBatch, FinalizeBatch, CancelBatch,
// ListBatches, SubscribeMintEvents) provided callers do not require a
// real on-chain confirmation.
type Mint struct {
	*Storage

	MintingStore *tapdb.AssetMintingStore
	Planter      *tapgarden.ChainPlanter
	ChainBridge  *tapnodemock.ChainBridge
	Wallet       *tapnodemock.WalletAnchor
	GenSigner    *tapgarden.MockGenSigner
}

// NewMint constructs a Mint fixture and registers cleanup. The Planter is
// started and stopped automatically.
func NewMint(tb testing.TB) *Mint {
	tb.Helper()

	st := NewStorage(tb)

	mintingExec := tapdb.NewTransactionExecutor(
		st.DB.BaseDB, func(tx *sql.Tx) tapdb.PendingAssetStore {
			return st.DB.WithTx(tx)
		},
	)
	mintingStore := tapdb.NewAssetMintingStore(mintingExec)
	treeMgr := tapgarden.NewFallibleTapscriptTreeMgr(mintingStore)

	chainBridge := tapnodemock.NewChainBridge()
	wallet := tapnodemock.NewWalletAnchor()
	genSigner := tapgarden.NewMockGenSigner(st.KeyRing)

	errChan := make(chan error, 16)

	planter := tapgarden.NewChainPlanter(tapgarden.PlanterConfig{
		GardenKit: tapgarden.GardenKit{
			Wallet:       wallet,
			ChainBridge:  chainBridge,
			BatchStore:   mintingStore,
			MintingRefs:  mintingStore,
			TreeStore:    &treeMgr,
			KeyRing:      st.KeyRing,
			GenSigner:    genSigner,
			GenTxBuilder: &tapscript.GroupTxBuilder{},
			TxValidator:  &tap.ValidatorV0{},
			ProofFiles:   proof.NewMockProofArchive(),
			ProofWatcher: &tapgarden.MockProofWatcher{},
		},
		ChainParams:  st.Config.ChainParams,
		ProofUpdates: proof.NewMockProofArchive(),
		ErrChan:      errChan,
	})
	require.NoError(tb, planter.Start())

	tb.Cleanup(func() {
		_ = planter.Stop()
	})

	st.Config.MintingStore = mintingStore
	st.Config.AssetMinter = planter
	st.Config.ChainBridge = chainBridge

	return &Mint{
		Storage:      st,
		MintingStore: mintingStore,
		Planter:      planter,
		ChainBridge:  chainBridge,
		Wallet:       wallet,
		GenSigner:    genSigner,
	}
}
