package asset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/json"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// RandGenesis creates a random genesis for testing.
func RandGenesis(t testing.TB, assetType asset.Type) asset.Genesis {
	t.Helper()

	var metaHash [32]byte
	test.RandRead(t, metaHash[:])

	return asset.Genesis{
		FirstPrevOut: test.RandOp(t),
		Tag:          hex.EncodeToString(metaHash[:]),
		MetaHash:     metaHash,
		OutputIndex:  uint32(test.RandInt[int32]()),
		Type:         assetType,
	}
}

// RandGroupKey creates a random group key for testing.
func RandGroupKey(t testing.TB, genesis asset.Genesis,
	newAsset *asset.Asset) *asset.GroupKey {

	groupKey, _ := RandGroupKeyWithSigner(t, genesis, newAsset)
	return groupKey
}

// RandGroupKeyWithSigner creates a random group key for testing, and provides
// the signer for reissuing assets into the same group.
func RandGroupKeyWithSigner(t testing.TB, genesis asset.Genesis,
	newAsset *asset.Asset) (*asset.GroupKey, []byte) {

	privateKey := test.RandPrivKey(t)

	genSigner := NewMockGenesisSigner(privateKey)
	genBuilder := MockGroupTxBuilder{}
	groupReq := asset.GroupKeyRequest{
		RawKey:    test.PubToKeyDesc(privateKey.PubKey()),
		AnchorGen: genesis,
		NewAsset:  newAsset,
	}
	genTx, err := groupReq.BuildGroupVirtualTx(&genBuilder)
	require.NoError(t, err)

	groupKey, err := asset.DeriveGroupKey(genSigner, *genTx, groupReq, nil)
	require.NoError(t, err)

	return groupKey, privateKey.Serialize()
}

// MockGenesisSigner implements the GenesisSigner interface using a raw
// private key.
type MockGenesisSigner struct {
	privKey *btcec.PrivateKey
}

// NewMockGenesisSigner creates a new MockGenesisSigner instance given the
// passed public key.
func NewMockGenesisSigner(priv *btcec.PrivateKey) *MockGenesisSigner {
	return &MockGenesisSigner{
		privKey: priv,
	}
}

// SignVirtualTx generates a signature according to the passed signing
// descriptor and virtual TX.
func (r *MockGenesisSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	virtualTx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature,
	error) {

	signerPubKey := r.privKey.PubKey()

	if !signDesc.KeyDesc.PubKey.IsEqual(signerPubKey) {
		return nil, fmt.Errorf("cannot sign with key")
	}

	sig, err := SignVirtualTx(r.privKey, signDesc, virtualTx, prevOut)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// A compile-time assertion to ensure MockGenesisSigner meets the
// GenesisSigner interface.
var _ asset.GenesisSigner = (*MockGenesisSigner)(nil)

// Forked from tapscript/tx/virtualTxOut to remove checks for split commitments
// and witness stripping.
func virtualGenesisTxOut(newAsset *asset.Asset) (*wire.TxOut, error) {
	// Commit to the new asset directly. In this case, the output script is
	// derived from the root of a MS-SMT containing the new asset.
	groupKey := schnorr.SerializePubKey(&newAsset.GroupKey.GroupPubKey)
	assetID := newAsset.Genesis.ID()

	h := sha256.New()
	_, _ = h.Write(groupKey)
	_, _ = h.Write(assetID[:])
	_, _ = h.Write(schnorr.SerializePubKey(newAsset.ScriptKey.PubKey))

	key := *(*[32]byte)(h.Sum(nil))
	leaf, err := newAsset.Leaf()
	if err != nil {
		return nil, err
	}
	outputTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	// TODO(bhandras): thread the context through.
	tree, err := outputTree.Insert(context.TODO(), key, leaf)
	if err != nil {
		return nil, err
	}

	treeRoot, err := tree.Root(context.Background())
	if err != nil {
		return nil, err
	}

	rootKey := treeRoot.NodeHash()
	pkScript, err := test.ComputeTaprootScriptErr(rootKey[:])
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(int64(newAsset.Amount), pkScript), nil
}

// Forked from tapscript/tx/virtualTx to be used only with the
// MockGroupTxBuilder.
func virtualGenesisTx(newAsset *asset.Asset) (*wire.MsgTx, error) {
	var (
		txIn *wire.TxIn
		err  error
	)

	// We'll start by mapping all inputs into a MS-SMT.
	txIn, _, err = asset.VirtualGenesisTxIn(newAsset)
	if err != nil {
		return nil, err
	}

	// Then we'll map all asset outputs into a single UTXO.
	txOut, err := virtualGenesisTxOut(newAsset)
	if err != nil {
		return nil, err
	}

	// With our single input and output mapped, we're ready to construct our
	// virtual transaction.
	virtualTx := wire.NewMsgTx(2)
	virtualTx.AddTxIn(txIn)
	virtualTx.AddTxOut(txOut)
	return virtualTx, nil
}

type MockGroupTxBuilder struct{}

// BuildGenesisTx constructs a virtual transaction and prevOut that represent
// the genesis state transition for a grouped asset. This output is used to
// create a group witness for the grouped asset.
func (m *MockGroupTxBuilder) BuildGenesisTx(newAsset *asset.Asset) (*wire.MsgTx,
	*wire.TxOut, error) {

	// First, we check that the passed asset is a genesis grouped asset
	// that has no group witness.
	if !newAsset.NeedsGenesisWitnessForGroup() {
		return nil, nil, fmt.Errorf("asset is not a genesis grouped " +
			"asset")
	}

	prevOut, err := asset.InputGenesisAssetPrevOut(*newAsset)
	if err != nil {
		return nil, nil, err
	}

	// Now, create the virtual transaction that represents this asset
	// minting.
	virtualTx, err := virtualGenesisTx(newAsset)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot tweak group key: %w", err)
	}
	populatedVirtualTx := asset.VirtualTxWithInput(
		virtualTx, newAsset.LockTime, newAsset.RelativeLockTime, 0, nil,
	)

	return populatedVirtualTx, prevOut, nil
}

// A compile time assertion to ensure that MockGroupTxBuilder meets the
// GenesisTxBuilder interface.
var _ asset.GenesisTxBuilder = (*MockGroupTxBuilder)(nil)

// SignOutputRaw creates a signature for a single input.
// Taken from lnd/lnwallet/btcwallet/signer:L344, SignOutputRaw
func SignOutputRaw(priv *btcec.PrivateKey, tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (*schnorr.Signature, error) {

	witnessScript := signDesc.WitnessScript

	privKey := priv
	var maybeTweakPrivKey *btcec.PrivateKey

	switch {
	case signDesc.SingleTweak != nil:
		maybeTweakPrivKey = input.TweakPrivKey(
			privKey, signDesc.SingleTweak,
		)

	case signDesc.DoubleTweak != nil:
		maybeTweakPrivKey = input.DeriveRevocationPrivKey(
			privKey, signDesc.DoubleTweak,
		)

	default:
		maybeTweakPrivKey = privKey
	}

	privKey = maybeTweakPrivKey

	// In case of a taproot output any signature is always a Schnorr
	// signature, based on the new tapscript sighash algorithm.
	if !txscript.IsPayToTaproot(signDesc.Output.PkScript) {
		return nil, fmt.Errorf("mock signer: output script not taproot")
	}

	sigHashes := txscript.NewTxSigHashes(
		tx, signDesc.PrevOutputFetcher,
	)

	// Are we spending a script path or the key path? The API is slightly
	// different, so we need to account for that to get the raw signature.
	var (
		rawSig []byte
		err    error
	)
	switch signDesc.SignMethod {
	case input.TaprootKeySpendBIP0086SignMethod,
		input.TaprootKeySpendSignMethod:

		// This function tweaks the private key using the tap root key
		// supplied as the tweak.
		rawSig, err = txscript.RawTxInTaprootSignature(
			tx, sigHashes, signDesc.InputIndex,
			signDesc.Output.Value, signDesc.Output.PkScript,
			signDesc.TapTweak, signDesc.HashType, privKey,
		)

	case input.TaprootScriptSpendSignMethod:
		leaf := txscript.TapLeaf{
			LeafVersion: txscript.BaseLeafVersion,
			Script:      witnessScript,
		}
		rawSig, err = txscript.RawTxInTapscriptSignature(
			tx, sigHashes, signDesc.InputIndex,
			signDesc.Output.Value, signDesc.Output.PkScript,
			leaf, signDesc.HashType, privKey,
		)
	default:
		// A witness V0 sign method should never appear here.
	}
	if err != nil {
		return nil, err
	}

	return schnorr.ParseSignature(rawSig)
}

func SignVirtualTx(priv *btcec.PrivateKey, signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)

	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	fullSignDesc := input.SignDescriptor{
		KeyDesc:           signDesc.KeyDesc,
		SingleTweak:       signDesc.SingleTweak,
		DoubleTweak:       signDesc.DoubleTweak,
		TapTweak:          signDesc.TapTweak,
		WitnessScript:     signDesc.WitnessScript,
		SignMethod:        signDesc.SignMethod,
		Output:            signDesc.Output,
		HashType:          signDesc.HashType,
		SigHashes:         sigHashes,
		PrevOutputFetcher: prevOutFetcher,
		InputIndex:        signDesc.InputIndex,
	}

	sig, err := SignOutputRaw(priv, tx, &fullSignDesc)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// AssetCustomGroupKey constructs a new asset group key and anchor asset from a
// given asset genesis. The asset group key may also commit to a Tapscript tree
// root. The tree used in that case includes a hash lock and signature lock.
// The validity of that Tapscript tree is set by the caller.
//
// The following group key derivation methods are supported:
//
// BIP86: The group key commits to an empty tapscript tree. Assets can only be
// added to the group with a valid signature from the tweaked group key.
//
// Key-spend: The group key commits to a tapscript tree root, but the witness
// for the group anchor will be a signature using the tweaked group key. Assets
// could later be added to the group with either a signature from the tweaked
// group key or a valid witness for a script in the committed tapscript tree.
//
// Script-spend: The group key commits to a tapscript tree root, and the witness
// for the group anchor is a valid script witness for a script in the tapscript
// tree. Assets could later be added to the group with either a signature from
// the tweaked group key or a valid witness for a script in the committed
// tapscript tree.
func AssetCustomGroupKey(t *testing.T, useHashLock, BIP86, keySpend,
	validScriptWitness bool, gen asset.Genesis) *asset.Asset {

	t.Helper()

	// Sanity check the custom group key request. If both flags are false,
	// the script-spend path will be used.
	if BIP86 && keySpend {
		require.Fail(t, "Cannot have both BIP 86 and key spend group "+
			"key types")
	}

	var groupKey *asset.GroupKey

	genID := gen.ID()
	scriptKey := RandScriptKey(t)
	protoAsset := RandAssetWithValues(t, gen, nil, scriptKey)

	groupPrivKey := test.RandPrivKey(t)
	groupInternalKey := groupPrivKey.PubKey()
	genSigner := NewMockGenesisSigner(groupPrivKey)
	genBuilder := MockGroupTxBuilder{}

	// Manually create and use the singly tweaked key here, to match the
	// signing behavior later when using the signing descriptor.
	groupSinglyTweakedKey := input.TweakPubKeyWithTweak(
		groupInternalKey, genID[:],
	)

	// Populate the initial parameters for the group key request.
	groupReq := asset.GroupKeyRequest{
		RawKey:    test.PubToKeyDesc(groupInternalKey),
		AnchorGen: gen,
		NewAsset:  protoAsset,
	}
	// Update the group key request and group key derivation arguments
	// to match the requested group key type.
	switch {
	// Use an empty tapscript and script witness.
	case BIP86:
		genTx, err := groupReq.BuildGroupVirtualTx(&genBuilder)
		require.NoError(t, err)

		groupKey, err = asset.DeriveGroupKey(
			genSigner, *genTx, groupReq, nil,
		)
		require.NoError(t, err)

	// Derive a tapscipt root using the default tapscript tree used for
	// testing, but use a signature as a witness.
	case keySpend:
		treeRootChildren := test.BuildTapscriptTreeNoReveal(
			t, groupSinglyTweakedKey,
		)
		treeTapHash := treeRootChildren.TapHash()

		groupReq.TapscriptRoot = treeTapHash[:]
		genTx, err := groupReq.BuildGroupVirtualTx(&genBuilder)
		require.NoError(t, err)

		groupKey, err = asset.DeriveGroupKey(
			genSigner, *genTx, groupReq, nil,
		)
		require.NoError(t, err)

	// For a script spend, we derive a tapscript root, and create the needed
	// tapscript and script witness.
	default:
		_, _, tapLeaf, tapRootHash, witness := test.BuildTapscriptTree(
			t, useHashLock, validScriptWitness,
			groupSinglyTweakedKey,
		)

		groupReq.TapscriptRoot = tapRootHash
		genTx, err := groupReq.BuildGroupVirtualTx(&genBuilder)
		require.NoError(t, err)

		switch {
		case witness != nil:
			groupKey, err = asset.AssembleGroupKeyFromWitness(
				*genTx, groupReq, tapLeaf, witness,
			)

		default:
			groupKey, err = asset.DeriveGroupKey(
				genSigner, *genTx, groupReq, tapLeaf,
			)
		}
		require.NoError(t, err)
	}

	return NewAssetNoErr(
		t, gen, protoAsset.Amount, protoAsset.LockTime,
		protoAsset.RelativeLockTime, scriptKey, groupKey,
		asset.WithAssetVersion(protoAsset.Version),
	)
}

// RandScriptKey creates a random script key for testing.
func RandScriptKey(t testing.TB) asset.ScriptKey {
	return asset.NewScriptKey(test.RandPrivKey(t).PubKey())
}

// RandSerializedKey creates a random serialized key for testing.
func RandSerializedKey(t testing.TB) asset.SerializedKey {
	return asset.ToSerialized(test.RandPrivKey(t).PubKey())
}

// RandID creates a random asset ID.
func RandID(t testing.TB) asset.ID {
	var a asset.ID
	test.RandRead(t, a[:])

	return a
}

// RandAssetType creates a random asset type.
func RandAssetType(t testing.TB) asset.Type {
	isCollectible := test.RandBool()
	if isCollectible {
		return asset.Collectible
	}

	return asset.Normal
}

// NewAssetNoErr creates an asset and fails the test if asset creation fails.
func NewAssetNoErr(t testing.TB, gen asset.Genesis, amt, locktime,
	relocktime uint64, scriptKey asset.ScriptKey, groupKey *asset.GroupKey,
	opts ...asset.NewAssetOpt) *asset.Asset {

	a, err := asset.New(
		gen, amt, locktime, relocktime, scriptKey, groupKey, opts...,
	)
	require.NoError(t, err)

	return a
}

func NewGroupKeyRequestNoErr(t testing.TB, internalKey keychain.KeyDescriptor,
	gen asset.Genesis, newAsset *asset.Asset,
	scriptRoot []byte) *asset.GroupKeyRequest {

	req, err := asset.NewGroupKeyRequest(
		internalKey, gen, newAsset, scriptRoot,
	)
	require.NoError(t, err)

	return req
}

// RandAsset creates a random asset of the given type for testing.
func RandAsset(t testing.TB, assetType asset.Type) *asset.Asset {
	t.Helper()

	genesis := RandGenesis(t, assetType)
	scriptKey := RandScriptKey(t)
	protoAsset := RandAssetWithValues(t, genesis, nil, scriptKey)
	familyKey := RandGroupKey(t, genesis, protoAsset)

	return NewAssetNoErr(
		t, genesis, protoAsset.Amount, protoAsset.LockTime,
		protoAsset.RelativeLockTime, scriptKey, familyKey,
		asset.WithAssetVersion(protoAsset.Version),
	)
}

// RandAssetWithValues creates a random asset with the given genesis and keys
// for testing.
func RandAssetWithValues(t testing.TB, genesis asset.Genesis,
	groupKey *asset.GroupKey, scriptKey asset.ScriptKey) *asset.Asset {

	t.Helper()

	units := test.RandInt[uint32]() + 1

	switch genesis.Type {
	case asset.Normal:

	case asset.Collectible:
		units = 1

	default:
		t.Fatal("unhandled asset type", genesis.Type)
	}

	var assetVersion asset.Version
	if test.RandInt[uint8]()%2 == 0 {
		assetVersion = asset.V1
	}

	return NewAssetNoErr(
		t, genesis, uint64(units), 0, 0, scriptKey, groupKey,
		asset.WithAssetVersion(assetVersion),
	)
}

type ValidTestCase struct {
	Asset    *json.Asset `json:"asset"`
	Expected string      `json:"expected"`
	Comment  string      `json:"comment"`
}

type ErrorTestCase struct {
	Asset   *json.Asset `json:"asset"`
	Error   string      `json:"error"`
	Comment string      `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}

type ValidBurnTestCase struct {
	PrevID   *json.PrevID `json:"prev_id"`
	Expected string       `json:"expected"`
	Comment  string       `json:"comment"`
}

type BurnTestVectors struct {
	ValidTestCases []*ValidBurnTestCase `json:"valid_test_cases"`
}
