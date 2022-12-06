package tarogarden

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/keychain"
)

// MintingBatch packages the pending state of a batch, this includes the batch
// key, the state of the batch and the assets to be created.
//
// TODO(roasbeef): split this up after all? into two struts? Either[A, B]?
type MintingBatch struct {
	// CreationTime is the time that this batch was created.
	CreationTime time.Time

	// HeightHint is the recorded block height at time of creating this
	// batch. We use it to know where to start looking for the signed batch
	// transaction.
	HeightHint uint32

	// BatchState is the state of the batch.
	BatchState BatchState

	// BatchKey is the unique identifier for a batch.
	BatchKey keychain.KeyDescriptor

	// Seedlings is the set of seedlings for this batch. This maps an
	// asset's name to the seedling itself.
	//
	// NOTE: This field is only set if the state is BatchStateFrozen or
	// BatchStatePending.
	Seedlings map[string]*Seedling

	// GenesisPacket is the funded genesis packet that may or may not be
	// fully signed. When broadcast, this will create all assets stored
	// within this batch.
	//
	// NOTE: This field is only set if the state is beyond
	// BatchStateCommitted.
	GenesisPacket *FundedPsbt

	// RootAssetCommitment is the root Taro commitment for all the assets
	// contained in this batch.
	//
	// NOTE: This field is only set if the state is beyond
	// BatchStateCommitted.
	RootAssetCommitment *commitment.TaroCommitment

	// mintingPubKey is the top-level Taproot output key that will be
	// used to commit to the Taro commitment above.
	mintingPubKey *btcec.PublicKey

	// taroScriptRoot is the root hash of the Taro commitment. If this is
	// nil, then the mintingPubKey will be as well.
	taroScriptRoot []byte
}

// TODO(roasbeef): add batch validate method re unique names?

// AddSeedling adds a new seedling to the batch.
func (m *MintingBatch) addSeedling(s *Seedling) error {
	if _, ok := m.Seedlings[s.AssetName]; ok {
		return fmt.Errorf("asset with name %v already in batch",
			s.AssetName)
	}

	m.Seedlings[s.AssetName] = s
	return nil
}

// MintingOutputKey derives the output key that once mined, will commit to the
// Taro asset root, thereby creating the set of included assets.
func (m *MintingBatch) MintingOutputKey() (*btcec.PublicKey, []byte, error) {
	if m.mintingPubKey != nil {
		return m.mintingPubKey, m.taroScriptRoot, nil
	}

	if m.RootAssetCommitment == nil {
		return nil, nil, fmt.Errorf("no asset commitment present")
	}

	taroScriptRoot := m.RootAssetCommitment.TapscriptRoot(nil)

	m.taroScriptRoot = taroScriptRoot[:]
	m.mintingPubKey = txscript.ComputeTaprootOutputKey(
		m.BatchKey.PubKey, taroScriptRoot[:],
	)

	return m.mintingPubKey, m.taroScriptRoot, nil
}

// genesisScript returns the script that should be placed in the minting output
// within the genesis transaction.
func (m *MintingBatch) genesisScript() ([]byte, error) {
	mintingOutputKey, _, err := m.MintingOutputKey()
	if err != nil {
		return nil, err
	}

	return taroscript.PayToTaprootScript(mintingOutputKey)
}
