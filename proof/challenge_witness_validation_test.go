package proof

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/stretchr/testify/require"
)

// reanchorProof recomputes the anchor commitment, inclusion proof and block
// merkle root of a proof after its asset was modified.
func reanchorProof(t *testing.T, p *Proof) {
	t.Helper()

	assetCommitment, err := commitment.NewAssetCommitment(&p.Asset)
	require.NoError(t, err)
	version := commitment.TapCommitmentV2
	tapCommitment, err := commitment.NewTapCommitment(
		&version, assetCommitment,
	)
	require.NoError(t, err)
	require.NoError(t, tapCommitment.MergeAltLeaves(p.AltLeaves))

	_, inclusionProof, err := tapCommitment.Proof(
		p.Asset.TapCommitmentKey(), p.Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	p.InclusionProof.CommitmentProof.Proof = *inclusionProof
	p.AnchorTx.TxOut[0].PkScript = outputScript(
		t, tapCommitment, p.InclusionProof.InternalKey,
	)
	txMerkleProof, err := NewTxMerkleProof([]*wire.MsgTx{&p.AnchorTx}, 0)
	require.NoError(t, err)
	p.TxMerkleProof = *txMerkleProof
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(&p.AnchorTx)}, false,
	)
	p.BlockHeader.MerkleRoot = *merkleTree[len(merkleTree)-1]
}

// signOwnershipWitness signs the ownership proof of the given asset with the
// key controlling its script key.
func signOwnershipWitness(t *testing.T, ownedAsset *asset.Asset,
	key *btcec.PrivateKey) wire.TxWitness {

	t.Helper()

	owned := ownedAsset.Copy()
	prevID, proofAsset := CreateOwnershipProofAsset(
		owned, fn.None[[32]byte](),
	)
	inputs := commitment.InputSet{prevID: owned}
	virtualTx, _, err := tapscript.VirtualTx(proofAsset, inputs)
	require.NoError(t, err)
	virtualTx = asset.VirtualTxWithInput(
		virtualTx, proofAsset.LockTime, proofAsset.RelativeLockTime,
		0, nil,
	)
	sigHash, err := tapscript.InputKeySpendSigHash(
		virtualTx, owned, proofAsset, 0, txscript.SigHashDefault,
	)
	require.NoError(t, err)
	taprootPrivKey := txscript.TweakTaprootPrivKey(*key, nil)
	sig, err := schnorr.Sign(taprootPrivKey, sigHash)
	require.NoError(t, err)

	return wire.TxWitness{sig.Serialize()}
}

// TestVerifyGenesisChallengeWitness verifies that a genesis proof carrying a
// challenge witness still runs the genesis transition checks.
func TestVerifyGenesisChallengeWitness(t *testing.T) {
	t.Parallel()

	amt := uint64(100)
	p, key := RandGenesisProofWithKey(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil,
		asset.V0,
	)

	groupPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	p.Asset.GroupKey = &asset.GroupKey{
		GroupPubKey: *groupPrivKey.PubKey(),
	}
	p.GroupKeyReveal = nil
	p.Asset.PrevWitnesses[0].TxWitness = nil
	reanchorProof(t, &p)
	p.ChallengeWitness = signOwnershipWitness(t, &p.Asset, key)

	// A full proof file has no use for a challenge witness, so the file
	// verifier rejects the proof before it reaches the transition checks.
	file, err := NewFile(V0, p)
	require.NoError(t, err)
	_, err = file.Verify(context.Background(), MockVerifierCtx)
	require.ErrorIs(t, err, ErrProofFileInvalid)

	// Verified standalone, as an ownership proof is, the genesis proof
	// still runs the genesis transition checks and the missing group
	// witness is caught.
	_, err = p.Verify(
		context.Background(), nil, MockChainLookup, MockVerifierCtx,
	)
	require.Error(t, err)

	var vmErr vm.Error
	require.ErrorAs(t, err, &vmErr)
	require.Equal(t, vm.ErrInvalidGenesisStateTransition, vmErr.Kind)
}
