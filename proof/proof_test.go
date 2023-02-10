package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

var (
	// proofFileHexFileName is the name of the file that contains the hex
	// proof file data.
	proofFileHexFileName = filepath.Join(testDataFileName, "proof-file.hex")
)

func assertEqualCommitmentProof(t *testing.T, expected, actual *CommitmentProof) {
	require.Equal(t, expected.Proof.AssetProof, actual.Proof.AssetProof)
	require.Equal(t, expected.Proof.TaroProof, actual.Proof.TaroProof)
	require.Equal(t, expected.TapSiblingPreimage, actual.TapSiblingPreimage)
}

func assertEqualTaprootProof(t *testing.T, expected, actual *TaprootProof) {
	t.Helper()
	require.Equal(t, expected.OutputIndex, actual.OutputIndex)
	require.Equal(t, expected.InternalKey, actual.InternalKey)
	if expected.CommitmentProof == nil {
		require.Nil(t, actual.CommitmentProof)
	} else {
		assertEqualCommitmentProof(
			t, expected.CommitmentProof, actual.CommitmentProof,
		)
	}
	if expected.TapscriptProof == nil {
		require.Nil(t, actual.TapscriptProof)
	} else {
		require.Equal(t, expected.TapscriptProof, actual.TapscriptProof)
	}
}

func assertEqualProof(t *testing.T, expected, actual *Proof) {
	t.Helper()
	require.Equal(t, expected.PrevOut, actual.PrevOut)
	require.Equal(t, expected.BlockHeader, actual.BlockHeader)
	require.Equal(t, expected.AnchorTx, actual.AnchorTx)
	require.Equal(t, expected.TxMerkleProof, actual.TxMerkleProof)
	require.Equal(t, expected.Asset, actual.Asset)
	assertEqualTaprootProof(t, &expected.InclusionProof, &actual.InclusionProof)
	for i := range expected.ExclusionProofs {
		assertEqualTaprootProof(
			t, &expected.ExclusionProofs[i], &actual.ExclusionProofs[i],
		)
	}
	require.Equal(t, expected.ExclusionProofs, actual.ExclusionProofs)
	if expected.SplitRootProof != nil {
		assertEqualTaprootProof(
			t, expected.SplitRootProof, actual.SplitRootProof,
		)
	} else {
		require.Nil(t, actual.SplitRootProof)
	}
	for i := range expected.AdditionalInputs {
		require.Equal(
			t, expected.AdditionalInputs[i].Version,
			actual.AdditionalInputs[i].Version,
		)
		require.Len(
			t, actual.AdditionalInputs,
			len(expected.AdditionalInputs),
		)
		for j := range expected.AdditionalInputs[i].proofs {
			e, err := expected.AdditionalInputs[i].ProofAt(uint32(j))
			require.NoError(t, err)

			a, err := actual.AdditionalInputs[i].ProofAt(uint32(j))
			require.NoError(t, err)
			assertEqualProof(t, e, a)
		}
	}
}

func TestProofEncoding(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	txMerkleProof, err := NewTxMerkleProof(oddTxBlock.Transactions, 0)
	require.NoError(t, err)

	genesis := asset.RandGenesis(t, asset.Collectible)
	groupKey := asset.RandGroupKey(t, genesis)

	commitment, assets, err := commitment.Mint(
		genesis, groupKey, &commitment.AssetDetails{
			Type:             asset.Collectible,
			ScriptKey:        test.PubToKeyDesc(test.RandPubKey(t)),
			Amount:           nil,
			LockTime:         1337,
			RelativeLockTime: 6,
		},
	)
	require.NoError(t, err)
	asset := assets[0]
	asset.GroupKey.RawKey = keychain.KeyDescriptor{}

	// Empty the raw script key, since we only serialize the tweaked
	// pubkey. We'll also force the main script key to be an x-only key as
	// well.
	asset.ScriptKey.PubKey, err = schnorr.ParsePubKey(
		schnorr.SerializePubKey(asset.ScriptKey.PubKey),
	)
	require.NoError(t, err)

	asset.ScriptKey.TweakedScriptKey = nil

	_, commitmentProof, err := commitment.Proof(
		asset.TaroCommitmentKey(), asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	proof := Proof{
		PrevOut:       genesis.FirstPrevOut,
		BlockHeader:   oddTxBlock.Header,
		AnchorTx:      *oddTxBlock.Transactions[0],
		TxMerkleProof: *txMerkleProof,
		Asset:         asset,
		InclusionProof: TaprootProof{
			OutputIndex: 1,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &CommitmentProof{
				Proof: *commitmentProof,
				TapSiblingPreimage: &TapscriptPreimage{
					SiblingPreimage: []byte{1},
					SiblingType:     LeafPreimage,
				},
			},
			TapscriptProof: nil,
		},
		ExclusionProofs: []TaprootProof{
			{
				OutputIndex: 2,
				InternalKey: test.RandPubKey(t),
				CommitmentProof: &CommitmentProof{
					Proof: *commitmentProof,
					TapSiblingPreimage: &TapscriptPreimage{
						SiblingPreimage: []byte{1},
						SiblingType:     LeafPreimage,
					},
				},
				TapscriptProof: nil,
			},
			{
				OutputIndex:     3,
				InternalKey:     test.RandPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &TapscriptProof{
					TapPreimage1: &TapscriptPreimage{
						SiblingPreimage: []byte{1},
						SiblingType:     BranchPreimage,
					},
					TapPreimage2: &TapscriptPreimage{
						SiblingPreimage: []byte{2},
						SiblingType:     LeafPreimage,
					},
					BIP86: true,
				},
			},
			{
				OutputIndex:     4,
				InternalKey:     test.RandPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &TapscriptProof{
					BIP86: true,
				},
			},
		},
		SplitRootProof: &TaprootProof{
			OutputIndex: 4,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: nil,
			},
		},
		AdditionalInputs: []File{},
	}
	file, err := NewFile(V0, proof, proof)
	require.NoError(t, err)
	proof.AdditionalInputs = []File{*file, *file}

	var buf bytes.Buffer
	require.NoError(t, proof.Encode(&buf))
	var decodedProof Proof
	require.NoError(t, decodedProof.Decode(&buf))

	assertEqualProof(t, &proof, &decodedProof)
}

func genRandomGenesisWithProof(t testing.TB, assetType asset.Type,
	amt *uint64, tapscriptPreimage *TapscriptPreimage) (Proof,
	*btcec.PrivateKey) {

	t.Helper()

	genesisPrivKey := test.RandPrivKey(t)
	assetGenesis := asset.RandGenesis(t, assetType)
	assetGroupKey := asset.RandGroupKey(t, assetGenesis)
	taroCommitment, assets, err := commitment.Mint(
		assetGenesis, assetGroupKey, &commitment.AssetDetails{
			Type: assetType,
			ScriptKey: test.PubToKeyDesc(
				genesisPrivKey.PubKey(),
			),
			Amount:           amt,
			LockTime:         0,
			RelativeLockTime: 0,
		},
	)
	require.NoError(t, err)
	genesisAsset := assets[0]
	_, commitmentProof, err := taroCommitment.Proof(
		genesisAsset.TaroCommitmentKey(),
		genesisAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	var tapscriptSibling *chainhash.Hash
	if tapscriptPreimage != nil {
		tapscriptSibling, err = tapscriptPreimage.TapHash()
		require.NoError(t, err)
	}

	internalKey := test.SchnorrPubKey(t, genesisPrivKey)
	tapscriptRoot := taroCommitment.TapscriptRoot(tapscriptSibling)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)
	taprootScript := test.ComputeTaprootScript(t, taprootKey)
	genesisTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			PkScript: taprootScript,
			Value:    330,
		}},
	}
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(genesisTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	blockHeader := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)

	txMerkleProof, err := NewTxMerkleProof([]*wire.MsgTx{genesisTx}, 0)
	require.NoError(t, err)

	return Proof{
		PrevOut:       genesisTx.TxIn[0].PreviousOutPoint,
		BlockHeader:   *blockHeader,
		AnchorTx:      *genesisTx,
		TxMerkleProof: *txMerkleProof,
		Asset:         genesisAsset,
		InclusionProof: TaprootProof{
			OutputIndex: 0,
			InternalKey: internalKey,
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: tapscriptPreimage,
			},
			TapscriptProof: nil,
		},
		ExclusionProofs:  nil,
		AdditionalInputs: nil,
	}, genesisPrivKey
}

func TestGenesisProofVerification(t *testing.T) {
	t.Parallel()

	// Create a script tree that we'll use for our tapscript sibling test
	// cases.
	scriptInternalKey := test.RandPrivKey(t).PubKey()
	leaf1 := test.ScriptHashLock(t, []byte("foobar"))
	leaf2 := test.ScriptSchnorrSig(t, scriptInternalKey)

	// The order doesn't matter here as they are sorted before hashing.
	branch := txscript.NewTapBranch(leaf1, leaf2)
	amount := uint64(5000)

	testCases := []struct {
		name              string
		assetType         asset.Type
		amount            *uint64
		tapscriptPreimage *TapscriptPreimage
	}{{
		name:      "collectible genesis",
		assetType: asset.Collectible,
	}, {
		name:              "collectible with leaf preimage",
		assetType:         asset.Collectible,
		tapscriptPreimage: NewPreimageFromLeaf(leaf1),
	}, {
		name:              "collectible with branch preimage",
		assetType:         asset.Collectible,
		tapscriptPreimage: NewPreimageFromBranch(branch),
	}, {
		name:      "normal genesis",
		assetType: asset.Normal,
		amount:    &amount,
	}, {
		name:              "normal with leaf preimage",
		assetType:         asset.Normal,
		amount:            &amount,
		tapscriptPreimage: NewPreimageFromLeaf(leaf1),
	}, {
		name:              "normal with branch preimage",
		assetType:         asset.Normal,
		amount:            &amount,
		tapscriptPreimage: NewPreimageFromBranch(branch),
	}}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(tt *testing.T) {
			genesisProof, _ := genRandomGenesisWithProof(
				tt, tc.assetType, tc.amount,
				tc.tapscriptPreimage,
			)
			_, err := genesisProof.Verify(
				context.Background(), nil, MockHeaderVerifier,
			)
			require.NoError(tt, err)
		})
	}
}

// TestProofBlockHeaderVerification ensures that an error returned by the
// HeaderVerifier callback is correctly propagated by the Verify proof method.
func TestProofBlockHeaderVerification(t *testing.T) {
	t.Parallel()

	proof, _ := genRandomGenesisWithProof(t, asset.Collectible, nil, nil)

	// Create a base reference for the block header. We will later modify
	// the proof block header.
	originalBlockHeader := proof.BlockHeader

	// Header verifier compares given header to expected header. Verifier
	// does not return error.
	errHeaderVerifier := fmt.Errorf("invalid block header")
	headerVerifier := func(blockHeader wire.BlockHeader) error {
		// Compare given block header against base reference block
		// header.
		if blockHeader != originalBlockHeader {
			return errHeaderVerifier
		}
		return nil
	}

	// Verify that the original proof block header is as expected and
	// therefore an error is not returned.
	_, err := proof.Verify(
		context.Background(), nil, headerVerifier,
	)
	require.NoError(t, err)

	// Modify proof block header, then check that the verification function
	// propagates the correct error.
	proof.BlockHeader.Nonce += 1
	_, actualErr := proof.Verify(
		context.Background(), nil, headerVerifier,
	)
	actualErrInner := errors.Unwrap(actualErr)
	require.Equal(t, actualErrInner, errHeaderVerifier)
}

// TestProofFileEncoding ensures that the proof file encoding and decoding works
// as expected.
func TestProofFileVerification(t *testing.T) {
	proofHex, err := os.ReadFile(proofFileHexFileName)
	require.NoError(t, err)

	proofBytes, err := hex.DecodeString(
		strings.Trim(string(proofHex), "\n"),
	)
	require.NoError(t, err)

	f := &File{}
	err = f.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	_, err = f.Verify(context.Background(), MockHeaderVerifier)
	require.NoError(t, err)
}

func BenchmarkProofEncoding(b *testing.B) {
	amt := uint64(5000)

	// Start with a minted genesis asset.
	genesisProof, _ := genRandomGenesisWithProof(
		b, asset.Normal, &amt, nil,
	)

	// We create a file with 10k proofs (the same one) and test encoding/
	// decoding performance.
	const numProofs = 10_000
	lotsOfProofs := make([]Proof, numProofs)
	for i := 0; i < numProofs; i++ {
		lotsOfProofs[i] = genesisProof
	}

	f, err := NewFile(V0, lotsOfProofs...)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	// Only this part is measured.
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		err = f.Encode(&buf)
		require.NoError(b, err)

		f2, err := NewFile(V0)
		require.NoError(b, err)

		err = f2.Decode(&buf)
		require.NoError(b, err)

		require.Len(b, f2.proofs, numProofs)
	}
}
