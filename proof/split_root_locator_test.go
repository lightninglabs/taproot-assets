package proof

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/stretchr/testify/require"
)

// splitFixture holds a split of a genesis asset into a root locator at
// output 0 and a receiver at output 1.
type splitFixture struct {
	genesisProof     *Proof
	genesisBlob      Blob
	genesisOutpoint  wire.OutPoint
	senderPrivKey    *btcec.PrivateKey
	rootAsset        *asset.Asset
	receiverAsset    *asset.Asset
	rootLocatorProof *mssmt.Proof
}

// newFullSplitFixture creates a full value split of a 100-unit genesis asset
// of the given asset version: the root locator is a zero-value, unspendable
// tombstone, the receiver gets all 100 units.
func newFullSplitFixture(t *testing.T,
	assetVersion asset.Version) *splitFixture {

	t.Helper()

	return newSplitFixture(
		t, asset.Normal, 100, assetVersion, 0, asset.NUMSCompressedKey,
		100,
	)
}

// newPartialSplitFixture creates a partial split of a 100-unit genesis asset
// of the given asset version: the root retains 60 units with a spendable
// script key, the receiver gets 40 units.
func newPartialSplitFixture(t *testing.T,
	assetVersion asset.Version) *splitFixture {

	t.Helper()

	rootPrivKey := test.RandPrivKey()
	rootScriptKey := asset.NewScriptKeyBip86(
		test.PubToKeyDesc(rootPrivKey.PubKey()),
	)

	return newSplitFixture(
		t, asset.Normal, 100, assetVersion, 60,
		asset.ToSerialized(rootScriptKey.PubKey), 40,
	)
}

// newCollectibleSplitFixture creates a split of a collectible genesis asset
// of the given asset version: the root locator is a zero-value, unspendable
// tombstone, the single receiver gets the collectible.
func newCollectibleSplitFixture(t *testing.T,
	assetVersion asset.Version) *splitFixture {

	t.Helper()

	return newSplitFixture(
		t, asset.Collectible, 1, assetVersion, 0,
		asset.NUMSCompressedKey, 1,
	)
}

// newSplitFixture creates a split of a genesis asset of the given type and
// total amount, with the root locator retaining rootAmount units under
// rootScriptKey and the receiver getting receiverAmount units.
func newSplitFixture(t *testing.T, assetType asset.Type, totalAmount uint64,
	assetVersion asset.Version, rootAmount uint64,
	rootScriptKey asset.SerializedKey,
	receiverAmount uint64) *splitFixture {

	t.Helper()

	genesisProof, senderPrivKey := genRandomGenesisWithProof(
		t, assetType, &totalAmount, nil, true, nil, nil, nil, nil,
		assetVersion,
	)
	genesisBlob, err := EncodeAsProofFile(&genesisProof)
	require.NoError(t, err)

	genesisOutpoint := wire.OutPoint{
		Hash:  genesisProof.AnchorTx.TxHash(),
		Index: genesisProof.InclusionProof.OutputIndex,
	}
	assetID := genesisProof.Asset.ID()

	receiverPrivKey := test.RandPrivKey()
	receiverScriptKey := asset.NewScriptKeyBip86(
		test.PubToKeyDesc(receiverPrivKey.PubKey()),
	)

	rootLocator := &commitment.SplitLocator{
		OutputIndex: 0,
		AssetID:     assetID,
		ScriptKey:   rootScriptKey,
		Amount:      rootAmount,
	}
	receiverLocator := &commitment.SplitLocator{
		OutputIndex: 1,
		AssetID:     assetID,
		ScriptKey:   asset.ToSerialized(receiverScriptKey.PubKey),
		Amount:      receiverAmount,
	}
	splitCommitment, err := commitment.NewSplitCommitment(
		context.Background(), []commitment.SplitCommitmentInput{{
			Asset:    &genesisProof.Asset,
			OutPoint: genesisOutpoint,
		}}, rootLocator, receiverLocator,
	)
	require.NoError(t, err)

	rootAsset := splitCommitment.RootAsset
	receiverAsset := &splitCommitment.SplitAssets[*receiverLocator].Asset
	rootLocatorProof := splitCommitment.SplitAssets[*rootLocator].
		PrevWitnesses[0].SplitCommitment.Proof

	signAssetTransfer(
		t, &genesisProof, rootAsset, senderPrivKey,
		[]*asset.Asset{receiverAsset},
	)

	return &splitFixture{
		genesisProof:     &genesisProof,
		genesisBlob:      genesisBlob,
		genesisOutpoint:  genesisOutpoint,
		senderPrivKey:    senderPrivKey,
		rootAsset:        rootAsset,
		receiverAsset:    receiverAsset,
		rootLocatorProof: &rootLocatorProof,
	}
}

// buildParams anchors the given root asset at output 0 and the given receiver
// asset at output 1 of a new anchor transaction and returns the transition
// proof parameters for both outputs.
func (f *splitFixture) buildParams(t *testing.T,
	rootAsset, receiverAsset *asset.Asset) (*TransitionParams,
	*TransitionParams) {

	t.Helper()

	receiverAssetNoSplitProof := receiverAsset.Copy()
	receiverAssetNoSplitProof.PrevWitnesses[0].SplitCommitment = nil

	rootAssetCommitment, err := commitment.NewAssetCommitment(rootAsset)
	require.NoError(t, err)
	rootTap, err := commitment.NewTapCommitment(nil, rootAssetCommitment)
	require.NoError(t, err)

	leafAssetCommitment, err := commitment.NewAssetCommitment(
		receiverAssetNoSplitProof,
	)
	require.NoError(t, err)
	leafTap, err := commitment.NewTapCommitment(nil, leafAssetCommitment)
	require.NoError(t, err)

	rootInternalKey := test.RandPubKey(t)
	leafInternalKey := test.RandPubKey(t)

	rootTapscriptRoot := rootTap.TapscriptRoot(nil)
	rootTaprootKey := txscript.ComputeTaprootOutputKey(
		rootInternalKey, rootTapscriptRoot[:],
	)
	leafTapscriptRoot := leafTap.TapscriptRoot(nil)
	leafTaprootKey := txscript.ComputeTaprootOutputKey(
		leafInternalKey, leafTapscriptRoot[:],
	)

	splitTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: f.genesisOutpoint,
		}},
		TxOut: []*wire.TxOut{{
			PkScript: test.ComputeTaprootScript(t, rootTaprootKey),
			Value:    330,
		}, {
			PkScript: test.ComputeTaprootScript(t, leafTaprootKey),
			Value:    330,
		}},
	}

	splitMerkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(splitTx)}, false,
	)
	splitMerkleRoot := splitMerkleTree[len(splitMerkleTree)-1]
	genesisHash := f.genesisProof.BlockHeader.BlockHash()
	splitBlockHeader := wire.NewBlockHeader(
		0, &genesisHash, splitMerkleRoot, 0, 0,
	)
	splitBlock := &wire.MsgBlock{
		Header:       *splitBlockHeader,
		Transactions: []*wire.MsgTx{splitTx},
	}

	_, rootInLeafExclusion, err := leafTap.Proof(
		rootAsset.TapCommitmentKey(), rootAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	_, leafInRootExclusion, err := rootTap.Proof(
		receiverAsset.TapCommitmentKey(),
		receiverAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	rootParams := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block:            splitBlock,
			Tx:               splitTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      rootInternalKey,
			TaprootAssetRoot: rootTap,
			ExclusionProofs: []TaprootProof{{
				OutputIndex: 1,
				InternalKey: leafInternalKey,
				CommitmentProof: &CommitmentProof{
					Proof: *rootInLeafExclusion,
				},
			}},
		},
		NewAsset:         rootAsset,
		RootLocatorProof: f.rootLocatorProof,
	}

	leafParams := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block:            splitBlock,
			Tx:               splitTx,
			TxIndex:          0,
			OutputIndex:      1,
			InternalKey:      leafInternalKey,
			TaprootAssetRoot: leafTap,
			ExclusionProofs: []TaprootProof{{
				OutputIndex: 0,
				InternalKey: rootInternalKey,
				CommitmentProof: &CommitmentProof{
					Proof: *leafInRootExclusion,
				},
			}},
		},
		NewAsset:             receiverAsset,
		RootInternalKey:      rootInternalKey,
		RootOutputIndex:      0,
		RootTaprootAssetTree: rootTap,
		RootLocatorProof:     f.rootLocatorProof,
	}

	return rootParams, leafParams
}

// TestSplitRootProof verifies that a split transition carrying the root
// locator's inclusion proof verifies, for both the root asset proof and the
// receiver asset proof.
func TestSplitRootProof(t *testing.T) {
	t.Parallel()

	for _, version := range []asset.Version{asset.V0, asset.V1} {
		t.Run(fmt.Sprintf("asset_v%d", version), func(t *testing.T) {
			t.Parallel()

			f := newFullSplitFixture(t, version)
			rootParams, leafParams := f.buildParams(
				t, f.rootAsset, f.receiverAsset,
			)

			genOpts := []GenOption{
				WithVersion(TransitionV0), WithNoSTXOProofs(),
			}

			rootBlob, rootProof, err := AppendTransition(
				f.genesisBlob, rootParams, MockVerifierCtx,
				genOpts...,
			)
			require.NoError(t, err)
			require.NotNil(t, rootProof.RootLocatorProof)
			verifyBlob(t, rootBlob)

			leafBlob, leafProof, err := AppendTransition(
				f.genesisBlob, leafParams, MockVerifierCtx,
				genOpts...,
			)
			require.NoError(t, err)
			require.NotNil(t, leafProof.RootLocatorProof)
			verifyBlob(t, leafBlob)
		})
	}
}

// TestSplitRootProofAmount verifies that a root asset whose amount differs
// from the root locator leaf committed in the split tree is rejected, for
// both the root asset proof and the receiver asset proof. The virtual
// transaction and its input signature remain valid, as does the anchor
// inclusion of the altered root.
func TestSplitRootProofAmount(t *testing.T) {
	t.Parallel()

	for _, version := range []asset.Version{asset.V0, asset.V1} {
		t.Run(fmt.Sprintf("asset_v%d", version), func(t *testing.T) {
			t.Parallel()

			f := newFullSplitFixture(t, version)

			// Alter the root asset: claim 1,000,000 units with a
			// fresh script key instead of the zero-value tombstone.
			// The split commitment root is unchanged, so the
			// virtual transaction (and its input signature) is
			// unaffected by the change.
			alteredRoot := f.rootAsset.Copy()
			alteredRoot.Amount = 1_000_000
			alteredRoot.ScriptKey = asset.NewScriptKeyBip86(
				test.PubToKeyDesc(test.RandPrivKey().PubKey()),
			)
			signAssetTransfer(
				t, f.genesisProof, alteredRoot, f.senderPrivKey,
				nil,
			)

			// The receiver's split commitment witness must embed
			// the altered root asset, so that the split root proof
			// anchors the exact same asset.
			alteredReceiver := f.receiverAsset.Copy()
			alteredReceiver.PrevWitnesses[0].SplitCommitment.
				RootAsset = *alteredRoot

			rootParams, leafParams := f.buildParams(
				t, alteredRoot, alteredReceiver,
			)

			genOpts := []GenOption{
				WithVersion(TransitionV0), WithNoSTXOProofs(),
			}

			// The proof of the altered root asset must be
			// rejected: the supplied root locator proof refers to
			// the zero-value leaf, which does not match the
			// reconstructed leaf with the altered amount.
			_, _, err := AppendTransition(
				f.genesisBlob, rootParams, MockVerifierCtx,
				genOpts...,
			)
			require.Error(t, err)
			var vmErr vm.Error
			require.ErrorAs(t, err, &vmErr)
			require.Equal(
				t, vm.ErrInvalidSplitCommitmentProof,
				vmErr.Kind,
			)

			// The proof of the receiver asset must be rejected for
			// the same reason, even though the receiver's own split
			// leaf is authentic.
			_, _, err = AppendTransition(
				f.genesisBlob, leafParams, MockVerifierCtx,
				genOpts...,
			)
			require.Error(t, err)
			require.ErrorAs(t, err, &vmErr)
			require.Equal(
				t, vm.ErrInvalidSplitCommitmentProof,
				vmErr.Kind,
			)
		})
	}
}

// TestSplitRootProofMismatch ensures that a split transition proof
// carrying a root locator proof that doesn't prove the reconstructed root
// locator leaf is rejected.
func TestSplitRootProofMismatch(t *testing.T) {
	t.Parallel()

	f := newFullSplitFixture(t, asset.V0)
	rootParams, _ := f.buildParams(t, f.rootAsset, f.receiverAsset)

	// Supply the receiver leaf's proof instead of the root locator's
	// proof.
	receiverProof := f.receiverAsset.PrevWitnesses[0].SplitCommitment.Proof
	rootParams.RootLocatorProof = &receiverProof

	genOpts := []GenOption{WithVersion(TransitionV0), WithNoSTXOProofs()}

	_, _, err := AppendTransition(
		f.genesisBlob, rootParams, MockVerifierCtx, genOpts...,
	)
	require.Error(t, err)
	var vmErr vm.Error
	require.ErrorAs(t, err, &vmErr)
	require.Equal(t, vm.ErrInvalidSplitCommitmentProof, vmErr.Kind)
}

// TestSplitRootProofPartial covers partial splits, where the root asset
// retains a non-zero amount under a spendable script key: the split verifies,
// and altering the root's amount while keeping the split tree is rejected.
func TestSplitRootProofPartial(t *testing.T) {
	t.Parallel()

	for _, version := range []asset.Version{asset.V0, asset.V1} {
		t.Run(fmt.Sprintf("asset_v%d", version), func(t *testing.T) {
			t.Parallel()

			f := newPartialSplitFixture(t, version)

			// The root asset of the partial split retains 60 units
			// under a spendable script key.
			require.Equal(t, uint64(60), f.rootAsset.Amount)
			require.False(t, f.rootAsset.IsUnSpendable())

			genOpts := []GenOption{
				WithVersion(TransitionV0), WithNoSTXOProofs(),
			}

			// The partial split verifies.
			rootParams, _ := f.buildParams(
				t, f.rootAsset, f.receiverAsset,
			)
			rootBlob, rootProof, err := AppendTransition(
				f.genesisBlob, rootParams, MockVerifierCtx,
				genOpts...,
			)
			require.NoError(t, err)
			require.NotNil(t, rootProof.RootLocatorProof)
			verifyBlob(t, rootBlob)

			// Alter the root's retained change from 60 to
			// 1,000,000 units. The split commitment root is
			// unchanged, so the virtual transaction and its input
			// signature remain valid, and the anchor commits to
			// the altered root.
			alteredRoot := f.rootAsset.Copy()
			alteredRoot.Amount = 1_000_000
			signAssetTransfer(
				t, f.genesisProof, alteredRoot, f.senderPrivKey,
				nil,
			)

			alteredParams, _ := f.buildParams(
				t, alteredRoot, f.receiverAsset,
			)
			_, _, err = AppendTransition(
				f.genesisBlob, alteredParams, MockVerifierCtx,
				genOpts...,
			)
			require.Error(t, err)
			var vmErr vm.Error
			require.ErrorAs(t, err, &vmErr)
			require.Equal(
				t, vm.ErrInvalidSplitCommitmentProof,
				vmErr.Kind,
			)
		})
	}
}

// TestSplitRootProofCollectible covers collectible splits, which take a
// stricter constructor path (zero-value unspendable root, single receiver):
// the split verifies, and a split whose root asset duplicates the collectible
// under a spendable script key is rejected.
func TestSplitRootProofCollectible(t *testing.T) {
	t.Parallel()

	for _, version := range []asset.Version{asset.V0, asset.V1} {
		t.Run(fmt.Sprintf("asset_v%d", version), func(t *testing.T) {
			t.Parallel()

			f := newCollectibleSplitFixture(t, version)

			// The root asset of the collectible split is a
			// zero-value, unspendable tombstone.
			require.Zero(t, f.rootAsset.Amount)
			require.True(t, f.rootAsset.IsUnSpendable())

			genOpts := []GenOption{
				WithVersion(TransitionV0), WithNoSTXOProofs(),
			}

			// The collectible split verifies, for both the root and
			// receiver proofs.
			rootParams, leafParams := f.buildParams(
				t, f.rootAsset, f.receiverAsset,
			)

			rootBlob, rootProof, err := AppendTransition(
				f.genesisBlob, rootParams, MockVerifierCtx,
				genOpts...,
			)
			require.NoError(t, err)
			require.NotNil(t, rootProof.RootLocatorProof)
			verifyBlob(t, rootBlob)

			leafBlob, _, err := AppendTransition(
				f.genesisBlob, leafParams, MockVerifierCtx,
				genOpts...,
			)
			require.NoError(t, err)
			verifyBlob(t, leafBlob)

			// Duplicate the collectible: the root asset claims
			// amount 1 under a spendable fresh key, while the split
			// tree only authenticates the zero-value tombstone root
			// locator and the receiver.
			dupRoot := f.rootAsset.Copy()
			dupRoot.Amount = 1
			dupRoot.ScriptKey = asset.NewScriptKeyBip86(
				test.PubToKeyDesc(test.RandPrivKey().PubKey()),
			)
			signAssetTransfer(
				t, f.genesisProof, dupRoot, f.senderPrivKey,
				nil,
			)

			dupParams, _ := f.buildParams(
				t, dupRoot, f.receiverAsset,
			)
			_, _, err = AppendTransition(
				f.genesisBlob, dupParams, MockVerifierCtx,
				genOpts...,
			)
			require.Error(t, err)
			var vmErr vm.Error
			require.ErrorAs(t, err, &vmErr)
			require.Equal(
				t, vm.ErrInvalidSplitCommitmentProof,
				vmErr.Kind,
			)
		})
	}
}
