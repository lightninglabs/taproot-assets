package tapfreighter

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
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

func assertOutputsEqual(t *testing.T, pkts []*tappsbt.VPacket,
	expectedOutputs [][]*tappsbt.VOutput) {

	t.Helper()

	require.Len(t, pkts, len(expectedOutputs))
	for i, pkt := range pkts {
		require.Len(t, pkt.Outputs, len(expectedOutputs[i]))
		require.Len(t, pkt.Inputs, 1)

		for j, out := range pkt.Outputs {
			expected := expectedOutputs[i][j]
			errCtx := fmt.Sprintf("packet %d, output %d", i, j)

			// We don't expect all fields to match, so we can't just
			// compare the outputs directly.
			require.Equal(t, expected.Amount, out.Amount, errCtx)
			require.Equal(
				t, expected.ScriptKey, out.ScriptKey, errCtx,
			)
			require.Equal(
				t, expected.Interactive, out.Interactive,
				errCtx,
			)
			require.Equal(t, expected.Type, out.Type, errCtx)
			require.Equal(
				t, expected.AnchorOutputIndex,
				out.AnchorOutputIndex, errCtx,
			)
			require.Equal(
				t, expected.AnchorOutputInternalKey,
				out.AnchorOutputInternalKey, errCtx,
			)
			require.Equal(
				t, expected.AltLeaves, out.AltLeaves, errCtx,
			)
			require.Equal(
				t, expected.AnchorOutputTapscriptSibling,
				out.AnchorOutputTapscriptSibling, errCtx,
			)
			require.Equal(
				t, expected.AssetVersion, out.AssetVersion,
				errCtx,
			)
			require.Equal(
				t, expected.LockTime, out.LockTime, errCtx,
			)
			require.Equal(
				t, expected.RelativeLockTime,
				out.RelativeLockTime, errCtx,
			)
			require.Equal(
				t, expected.ProofDeliveryAddress,
				out.ProofDeliveryAddress, errCtx,
			)

			// We do expect the BIP-0032 derivations to be set on
			// the resulting anchor outputs. But we can't really
			// assert their values, just that they're set.
			require.Len(
				t, out.AnchorOutputBip32Derivation, 1, errCtx,
			)
			require.Len(
				t, out.AnchorOutputTaprootBip32Derivation, 1,
				errCtx,
			)
		}
	}
}

// TestFundPacket tests that a virtual packet is created correctly from the
// combination of a funding template and the actual selected inputs. This
// includes anchor output key generation and assertion of a change or tombstone
// output.
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
		name                     string
		fundDesc                 *tapsend.FundingDescriptor
		vPkt                     *tappsbt.VPacket
		selectedCommitments      []*AnchoredCommitment
		keysDerived              int
		expectedErr              string
		expectedInputCommitments tappsbt.InputCommitments
		expectedOutputs          func(*testing.T,
			*tapgarden.MockKeyRing) [][]*tappsbt.VOutput
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
			expectedInputCommitments: tappsbt.InputCommitments{
				inputPrevID: inputCommitment,
			},
			expectedOutputs: func(t *testing.T,
				r *tapgarden.MockKeyRing) [][]*tappsbt.VOutput {

				pkt0Outputs := []*tappsbt.VOutput{{
					Amount:    20,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 0,
				}, {
					Amount:    mintAmount - 20,
					Type:      tappsbt.TypeSplitRoot,
					ScriptKey: r.ScriptKeyAt(t, 0),
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 2,
					),
					AnchorOutputIndex: 1,
				}}

				return [][]*tappsbt.VOutput{pkt0Outputs}
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
					Amount:            mintAmount,
					ScriptKey:         scriptKey,
					Interactive:       false,
					AnchorOutputIndex: 1,
				}},
			},
			selectedCommitments: []*AnchoredCommitment{{
				AnchorPoint: inputProof.OutPoint(),
				InternalKey: internalKey,
				Commitment:  inputCommitment,
				Asset:       &inputAsset,
			}},
			keysDerived: 2,
			expectedInputCommitments: tappsbt.InputCommitments{
				inputPrevID: inputCommitment,
			},
			expectedOutputs: func(t *testing.T,
				r *tapgarden.MockKeyRing) [][]*tappsbt.VOutput {

				pkt0Outputs := []*tappsbt.VOutput{{
					Amount:    0,
					Type:      tappsbt.TypeSplitRoot,
					ScriptKey: asset.NUMSScriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 0,
					),
					AnchorOutputIndex: 0,
				}, {
					Amount:    mintAmount,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 1,
				}}

				return [][]*tappsbt.VOutput{pkt0Outputs}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			exporter := &mockExporter{
				singleProof: inputProof,
			}
			addrBook := &mockAddrBook{}
			keyRing := tapgarden.NewMockKeyRing()

			result, err := createFundedPacketWithInputs(
				ctx, exporter, keyRing, addrBook,
				tc.fundDesc, tc.vPkt, tc.selectedCommitments,
			)

			keyRing.AssertNumberOfCalls(
				tt, "DeriveNextKey", tc.keysDerived,
			)

			if tc.expectedErr != "" {
				require.ErrorContains(tt, err, tc.expectedErr)

				return
			}

			require.NoError(tt, err)
			require.NotNil(tt, result)

			require.Equal(
				tt, tc.expectedInputCommitments,
				result.InputCommitments,
			)
			assertOutputsEqual(
				tt, result.VPackets,
				tc.expectedOutputs(tt, keyRing),
			)
		})
	}
}
