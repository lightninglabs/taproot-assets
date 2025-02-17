package tapfreighter

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

var (
	testParams = &address.RegressionNetTap

	oddTxBlockHexFileName = "../proof/testdata/odd-block.hex"
)

type mockExporter struct {
	singleProof proof.Proof
}

func (m *mockExporter) FetchProof(context.Context,
	proof.Locator) (proof.Blob, error) {

	f, err := proof.NewFile(proof.V0, m.singleProof)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = f.Encode(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

var _ proof.Exporter = (*mockExporter)(nil)

type mockAddrBook struct {
	scriptKeys []asset.TweakedScriptKey
}

func (m *mockAddrBook) FetchScriptKey(_ context.Context,
	tweakedScriptKey *btcec.PublicKey) (*asset.TweakedScriptKey, error) {

	for _, key := range m.scriptKeys {
		tweakedKey := txscript.ComputeTaprootOutputKey(
			key.RawKey.PubKey, key.Tweak,
		)
		if tweakedKey.IsEqual(tweakedScriptKey) {
			return &key, nil
		}
	}

	return nil, address.ErrScriptKeyNotFound
}

func (m *mockAddrBook) FetchInternalKeyLocator(_ context.Context,
	_ *btcec.PublicKey) (keychain.KeyLocator, error) {

	panic("not implemented")
}

var _ AddrBook = (*mockAddrBook)(nil)

func randProof(t *testing.T, amount uint64,
	internalKey keychain.KeyDescriptor) proof.Proof {

	oddTxBlockHex, err := os.ReadFile(oddTxBlockHexFileName)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(oddTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	var oddTxBlock wire.MsgBlock
	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	randGen := asset.RandGenesis(t, asset.Normal)
	scriptKey := test.RandPubKey(t)

	txMerkleProof := proof.TxMerkleProof{}
	mintCommitment, assets, err := commitment.Mint(
		nil, randGen, nil, &commitment.AssetDetails{
			Type:             randGen.Type,
			ScriptKey:        test.PubToKeyDesc(scriptKey),
			Amount:           &amount,
			LockTime:         1337,
			RelativeLockTime: 6,
		},
	)
	require.NoError(t, err)
	proofAsset := assets[0]

	// Empty the raw script key, since we only serialize the tweaked
	// pubkey. We'll also force the main script key to be an x-only key as
	// well.
	proofAsset.ScriptKey.PubKey, err = schnorr.ParsePubKey(
		schnorr.SerializePubKey(proofAsset.ScriptKey.PubKey),
	)
	require.NoError(t, err)

	proofAsset.ScriptKey.TweakedScriptKey = nil

	_, commitmentProof, err := mintCommitment.Proof(
		proofAsset.TapCommitmentKey(), proofAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	pkScript, _, _, err := tapsend.AnchorOutputScript(
		internalKey.PubKey, nil, mintCommitment,
	)
	require.NoError(t, err)

	anchorTx := wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			Value:    1000,
			PkScript: pkScript,
		}},
	}

	return proof.Proof{
		PrevOut:       randGen.FirstPrevOut,
		BlockHeight:   42,
		AnchorTx:      anchorTx,
		TxMerkleProof: txMerkleProof,
		Asset:         *proofAsset,
		InclusionProof: proof.TaprootProof{
			OutputIndex: 0,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &proof.CommitmentProof{
				Proof: *commitmentProof,
			},
		},
		MetaReveal: &proof.MetaReveal{
			Data: []byte("quoth the raven nevermore"),
			Type: proof.MetaOpaque,
		},
		GenesisReveal: &randGen,
	}
}

func TestFundPacket(t *testing.T) {
	ctx := context.Background()

	internalKey, _ := test.RandKeyDesc(t)
	scriptKey := asset.RandScriptKey(t)

	const mintAmount = 500
	inputProof := randProof(t, mintAmount, internalKey)
	inputAsset := inputProof.Asset
	assetID := inputAsset.ID()

	inputPrevID := asset.PrevID{
		OutPoint:  inputProof.OutPoint(),
		ID:        assetID,
		ScriptKey: asset.ToSerialized(inputAsset.ScriptKey.PubKey),
	}

	inputCommitment, err := commitment.FromAssets(nil, &inputProof.Asset)
	require.NoError(t, err)

	testCases := []struct {
		name                string
		fundDesc            *tapsend.FundingDescriptor
		vPkt                *tappsbt.VPacket
		selectedCommitments []*AnchoredCommitment
		keysDerived         int
		expectedErr         string
		validate            func(*testing.T, *FundedVPacket,
			*tapgarden.MockKeyRing)
	}{
		{
			name: "single input, no change present",
			fundDesc: &tapsend.FundingDescriptor{
				AssetSpecifier: asset.NewSpecifierFromId(
					assetID,
				),
				Amount: 20,
			},
			vPkt: &tappsbt.VPacket{
				ChainParams: testParams,
				Outputs: []*tappsbt.VOutput{{
					Amount:      20,
					ScriptKey:   scriptKey,
					Interactive: false,
				}},
			},
			selectedCommitments: []*AnchoredCommitment{{
				AnchorPoint: inputProof.OutPoint(),
				InternalKey: internalKey,
				Commitment:  inputCommitment,
				Asset:       &inputAsset,
			}},
			keysDerived: 3,
			validate: func(t *testing.T, r *FundedVPacket,
				kr *tapgarden.MockKeyRing) {

				inputCommitments := tappsbt.InputCommitments{
					inputPrevID: inputCommitment,
				}
				require.Equal(
					t, inputCommitments, r.InputCommitments,
				)

				require.Len(t, r.VPacket.Outputs, 2)
				require.Len(t, r.VPacket.Inputs, 1)

				vOut0 := r.VPacket.Outputs[0]
				require.Equal(t, uint64(20), vOut0.Amount)
				require.Equal(t, scriptKey, vOut0.ScriptKey)
				require.Equal(
					t, kr.PubKeyAt(t, 1),
					vOut0.AnchorOutputInternalKey,
				)

				vOut1 := r.VPacket.Outputs[1]
				require.Equal(
					t, uint64(mintAmount-20), vOut1.Amount,
				)
				require.Equal(
					t, kr.ScriptKeyAt(t, 0),
					vOut1.ScriptKey,
				)
				require.Equal(
					t, kr.PubKeyAt(t, 2),
					vOut1.AnchorOutputInternalKey,
				)
			},
		},
		{
			name: "single input, full value, no change present",
			fundDesc: &tapsend.FundingDescriptor{
				AssetSpecifier: asset.NewSpecifierFromId(
					assetID,
				),
				Amount: mintAmount,
			},
			vPkt: &tappsbt.VPacket{
				ChainParams: testParams,
				Outputs: []*tappsbt.VOutput{{
					Amount:      mintAmount,
					ScriptKey:   scriptKey,
					Interactive: false,
				}},
			},
			selectedCommitments: []*AnchoredCommitment{{
				AnchorPoint: inputProof.OutPoint(),
				InternalKey: internalKey,
				Commitment:  inputCommitment,
				Asset:       &inputAsset,
			}},
			keysDerived: 1,
			expectedErr: "single output must be interactive",
		},
		{
			name: "single input, full value, change present",
			fundDesc: &tapsend.FundingDescriptor{
				AssetSpecifier: asset.NewSpecifierFromId(
					assetID,
				),
				Amount: mintAmount,
			},
			vPkt: &tappsbt.VPacket{
				ChainParams: testParams,
				Outputs: []*tappsbt.VOutput{{
					Type:        tappsbt.TypeSplitRoot,
					Amount:      0,
					ScriptKey:   asset.NUMSScriptKey,
					Interactive: false,
				}, {
					Amount:      mintAmount,
					ScriptKey:   scriptKey,
					Interactive: false,
				}},
			},
			selectedCommitments: []*AnchoredCommitment{{
				AnchorPoint: inputProof.OutPoint(),
				InternalKey: internalKey,
				Commitment:  inputCommitment,
				Asset:       &inputAsset,
			}},
			keysDerived: 2,
			validate: func(t *testing.T, r *FundedVPacket,
				kr *tapgarden.MockKeyRing) {

				inputCommitments := tappsbt.InputCommitments{
					inputPrevID: inputCommitment,
				}
				require.Equal(
					t, inputCommitments, r.InputCommitments,
				)

				require.Len(t, r.VPacket.Outputs, 2)
				require.Len(t, r.VPacket.Inputs, 1)

				vOut0 := r.VPacket.Outputs[0]
				require.Equal(t, uint64(0), vOut0.Amount)
				require.Equal(
					t, asset.NUMSScriptKey,
					vOut0.ScriptKey,
				)
				require.Equal(
					t, kr.PubKeyAt(t, 0),
					vOut0.AnchorOutputInternalKey,
				)

				vOut1 := r.VPacket.Outputs[1]
				require.Equal(
					t, uint64(mintAmount), vOut1.Amount,
				)
				require.Equal(t, scriptKey, vOut1.ScriptKey)
				require.Equal(
					t, kr.PubKeyAt(t, 1),
					vOut1.AnchorOutputInternalKey,
				)
			},
		},
	}

	for _, tc := range testCases {
		exporter := &mockExporter{
			singleProof: inputProof,
		}
		addrBook := &mockAddrBook{}
		keyRing := tapgarden.NewMockKeyRing()

		result, err := fundPacketWithInputs(
			ctx, exporter, keyRing, addrBook,
			tc.fundDesc, tc.vPkt, tc.selectedCommitments,
		)

		keyRing.AssertNumberOfCalls(t, "DeriveNextKey", tc.keysDerived)

		if tc.expectedErr != "" {
			require.ErrorContains(t, err, tc.expectedErr)

			continue
		}

		require.NoError(t, err)
		require.NotNil(t, result)
		tc.validate(t, result, keyRing)
	}
}
