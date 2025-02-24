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
	"github.com/lightninglabs/taproot-assets/fn"
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
	proofs []*proof.Proof
}

func (m *mockExporter) FetchProof(_ context.Context,
	loc proof.Locator) (proof.Blob, error) {

	singleProof, err := fn.First(m.proofs, func(p *proof.Proof) bool {
		return p.Asset.ScriptKey.PubKey.IsEqual(&loc.ScriptKey)
	})
	if err != nil {
		return nil, err
	}

	f, err := proof.NewFile(proof.V0, *singleProof)
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

func randProof(t *testing.T, amount uint64, internalKey keychain.KeyDescriptor,
	groupKey *asset.GroupKey) proof.Proof {

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
		nil, randGen, groupKey, &commitment.AssetDetails{
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
	grpInternalKey1, _ := test.RandKeyDesc(t)
	grpInternalKey2, _ := test.RandKeyDesc(t)
	scriptKey := asset.RandScriptKey(t)

	const mintAmount = 500
	inputProof := randProof(t, mintAmount, internalKey, nil)
	inputAsset := inputProof.Asset
	assetID := inputAsset.ID()

	inputPrevID := asset.PrevID{
		OutPoint:  inputProof.OutPoint(),
		ID:        assetID,
		ScriptKey: asset.ToSerialized(inputAsset.ScriptKey.PubKey),
	}

	inputCommitment, err := commitment.FromAssets(nil, &inputProof.Asset)
	require.NoError(t, err)

	groupPubKey := test.RandPubKey(t)
	groupKey := &asset.GroupKey{
		GroupPubKey: *groupPubKey,
	}

	groupProof1 := randProof(t, mintAmount*2, grpInternalKey1, groupKey)
	groupInputAsset1 := groupProof1.Asset
	groupAssetID1 := groupInputAsset1.ID()

	groupProof2 := randProof(t, mintAmount*2, grpInternalKey2, groupKey)
	groupInputAsset2 := groupProof2.Asset
	groupAssetID2 := groupInputAsset2.ID()

	grpInputPrevID1 := asset.PrevID{
		OutPoint: groupProof1.OutPoint(),
		ID:       groupAssetID1,
		ScriptKey: asset.ToSerialized(
			groupInputAsset1.ScriptKey.PubKey,
		),
	}
	grpInputPrevID2 := asset.PrevID{
		OutPoint: groupProof2.OutPoint(),
		ID:       groupAssetID2,
		ScriptKey: asset.ToSerialized(
			groupInputAsset2.ScriptKey.PubKey,
		),
	}

	grpInputCommitment1, err := commitment.FromAssets(
		nil, &groupInputAsset1,
	)
	require.NoError(t, err)
	grpInputCommitment2, err := commitment.FromAssets(
		nil, &groupInputAsset2,
	)
	require.NoError(t, err)

	testCases := []struct {
		name                     string
		fundDesc                 *tapsend.FundingDescriptor
		vPkt                     *tappsbt.VPacket
		inputProofs              []*proof.Proof
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
			inputProofs: []*proof.Proof{&inputProof},
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
					Amount:    mintAmount - 20,
					Type:      tappsbt.TypeSplitRoot,
					ScriptKey: r.ScriptKeyAt(t, 0),
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 1,
				}, {
					Amount:    20,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 2,
					),
					AnchorOutputIndex: 0,
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
			inputProofs: []*proof.Proof{&inputProof},
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
					AnchorOutputIndex: 1,
				}, {
					Amount:    mintAmount,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 0,
				}}

				return [][]*tappsbt.VOutput{pkt0Outputs}
			},
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
			inputProofs: []*proof.Proof{&inputProof},
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
		{
			name: "multi input, full value, change present",
			fundDesc: &tapsend.FundingDescriptor{
				AssetSpecifier: asset.NewSpecifierFromGroupKey(
					*groupPubKey,
				),
				Amount: mintAmount * 4,
			},
			vPkt: &tappsbt.VPacket{
				ChainParams: testParams,
				Outputs: []*tappsbt.VOutput{{
					Type:        tappsbt.TypeSplitRoot,
					Amount:      0,
					ScriptKey:   asset.NUMSScriptKey,
					Interactive: false,
				}, {
					Amount:            mintAmount * 4,
					ScriptKey:         scriptKey,
					Interactive:       false,
					AnchorOutputIndex: 1,
				}},
			},
			inputProofs: []*proof.Proof{&groupProof1, &groupProof2},
			selectedCommitments: []*AnchoredCommitment{{
				AnchorPoint: groupProof1.OutPoint(),
				InternalKey: grpInternalKey1,
				Commitment:  grpInputCommitment1,
				Asset:       &groupInputAsset1,
			}, {
				AnchorPoint: groupProof2.OutPoint(),
				InternalKey: grpInternalKey2,
				Commitment:  grpInputCommitment2,
				Asset:       &groupInputAsset2,
			}},
			keysDerived: 2,
			expectedInputCommitments: tappsbt.InputCommitments{
				grpInputPrevID1: grpInputCommitment1,
				grpInputPrevID2: grpInputCommitment2,
			},
			// We test that we have two virtual packets, both with
			// one input and two outputs. In the first vOutput, we
			// always each have the tombstone zero-value output,
			// since this is a full-value spend across two vPackets.
			// The vOutputs across the two vPackets should each go
			// to the same anchor output. And the same anchor output
			// key should be derived for the same output indexes.
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
					Amount:    mintAmount * 2,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 1,
				}}
				pkt1Outputs := []*tappsbt.VOutput{{
					Amount:    0,
					Type:      tappsbt.TypeSplitRoot,
					ScriptKey: asset.NUMSScriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 0,
					),
					AnchorOutputIndex: 0,
				}, {
					Amount:    mintAmount * 2,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 1,
				}}

				// Actually, the two vPackets should be the
				// same, just different inputs.
				require.Equal(t, pkt0Outputs, pkt1Outputs)

				return [][]*tappsbt.VOutput{
					pkt0Outputs, pkt1Outputs,
				}
			},
		},
		{
			name: "multi input, partial amount, no change present",
			fundDesc: &tapsend.FundingDescriptor{
				AssetSpecifier: asset.NewSpecifierFromGroupKey(
					*groupPubKey,
				),
				Amount: mintAmount * 3,
			},
			vPkt: &tappsbt.VPacket{
				ChainParams: testParams,
				Outputs: []*tappsbt.VOutput{{
					Amount:      mintAmount * 3,
					ScriptKey:   scriptKey,
					Interactive: false,
				}},
			},
			inputProofs: []*proof.Proof{&groupProof1, &groupProof2},
			selectedCommitments: []*AnchoredCommitment{{
				AnchorPoint: groupProof1.OutPoint(),
				InternalKey: grpInternalKey1,
				Commitment:  grpInputCommitment1,
				Asset:       &groupInputAsset1,
			}, {
				AnchorPoint: groupProof2.OutPoint(),
				InternalKey: grpInternalKey2,
				Commitment:  grpInputCommitment2,
				Asset:       &groupInputAsset2,
			}},
			keysDerived: 3,
			expectedInputCommitments: tappsbt.InputCommitments{
				grpInputPrevID1: grpInputCommitment1,
				grpInputPrevID2: grpInputCommitment2,
			},
			// We test that we have two virtual packets, both with
			// one input and two outputs. In the first vOutput, we
			// always each have the tombstone zero-value output,
			// since this is a full-value spend across two vPackets.
			// The vOutputs across the two vPackets should each go
			// to the same anchor output. And the same anchor output
			// key should be derived for the same output indexes.
			expectedOutputs: func(t *testing.T,
				r *tapgarden.MockKeyRing) [][]*tappsbt.VOutput {

				pkt0Outputs := []*tappsbt.VOutput{{
					Amount:    mintAmount,
					Type:      tappsbt.TypeSplitRoot,
					ScriptKey: r.ScriptKeyAt(t, 0),
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 1,
				}, {
					Amount:    mintAmount,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 2,
					),
					AnchorOutputIndex: 0,
				}}
				pkt1Outputs := []*tappsbt.VOutput{{
					Amount:    0,
					Type:      tappsbt.TypeSplitRoot,
					ScriptKey: asset.NUMSScriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 1,
				}, {
					Amount:    mintAmount * 2,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 2,
					),
					AnchorOutputIndex: 0,
				}}

				return [][]*tappsbt.VOutput{
					pkt0Outputs, pkt1Outputs,
				}
			},
		},
		{
			name: "multi input, partial amount, change present",
			fundDesc: &tapsend.FundingDescriptor{
				AssetSpecifier: asset.NewSpecifierFromGroupKey(
					*groupPubKey,
				),
				Amount: mintAmount * 3,
			},
			vPkt: &tappsbt.VPacket{
				ChainParams: testParams,
				Outputs: []*tappsbt.VOutput{{
					Type:        tappsbt.TypeSplitRoot,
					Amount:      0,
					ScriptKey:   asset.NUMSScriptKey,
					Interactive: false,
				}, {
					Amount:            mintAmount * 3,
					ScriptKey:         scriptKey,
					Interactive:       false,
					AnchorOutputIndex: 1,
				}},
			},
			inputProofs: []*proof.Proof{&groupProof1, &groupProof2},
			selectedCommitments: []*AnchoredCommitment{{
				AnchorPoint: groupProof1.OutPoint(),
				InternalKey: grpInternalKey1,
				Commitment:  grpInputCommitment1,
				Asset:       &groupInputAsset1,
			}, {
				AnchorPoint: groupProof2.OutPoint(),
				InternalKey: grpInternalKey2,
				Commitment:  grpInputCommitment2,
				Asset:       &groupInputAsset2,
			}},
			keysDerived: 3,
			expectedInputCommitments: tappsbt.InputCommitments{
				grpInputPrevID1: grpInputCommitment1,
				grpInputPrevID2: grpInputCommitment2,
			},
			// We test that we have two virtual packets, both with
			// one input and two outputs. The first vPacket will be
			// a full-value spend, so the change should be the NUMS
			// key. The second vPacket is a partial spend, so there
			// should be change and a key derived for it. The
			// vOutputs across the two vPackets should each go to
			// the same anchor output. And the same anchor output
			// key should be derived for the same output indexes.
			expectedOutputs: func(t *testing.T,
				r *tapgarden.MockKeyRing) [][]*tappsbt.VOutput {

				pkt0Outputs := []*tappsbt.VOutput{{
					Amount:    mintAmount,
					Type:      tappsbt.TypeSplitRoot,
					ScriptKey: r.ScriptKeyAt(t, 0),
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 0,
				}, {
					Amount:    mintAmount,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 2,
					),
					AnchorOutputIndex: 1,
				}}
				pkt1Outputs := []*tappsbt.VOutput{{
					Amount:    0,
					Type:      tappsbt.TypeSplitRoot,
					ScriptKey: asset.NUMSScriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 1,
					),
					AnchorOutputIndex: 0,
				}, {
					Amount:    mintAmount * 2,
					Type:      tappsbt.TypeSimple,
					ScriptKey: scriptKey,
					AnchorOutputInternalKey: r.PubKeyAt(
						t, 2,
					),
					AnchorOutputIndex: 1,
				}}

				return [][]*tappsbt.VOutput{
					pkt0Outputs, pkt1Outputs,
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			exporter := &mockExporter{
				proofs: tc.inputProofs,
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
