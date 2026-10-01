package proof

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// rootParams returns the parameters for the proof of the root asset of the
// given split, including the exclusion proofs for all the other outputs of the
// anchor transaction.
func (a *testSplitAnchor) rootParams(t *testing.T,
	split *testSplit) *TransitionParams {

	t.Helper()

	stxoAssets, err := asset.CollectSTXO(split.root)
	require.NoError(t, err)

	var exclusionProofs []TaprootProof
	for outIdx := uint32(0); outIdx < uint32(len(a.tx.TxOut)); outIdx++ {
		if outIdx == split.rootOutput {
			continue
		}

		exclusionProof := TaprootProof{
			OutputIndex: outIdx,
			InternalKey: a.internalKeys[outIdx],
		}

		tree, ok := a.trees[outIdx]
		if !ok {
			exclusionProof.TapscriptProof = &TapscriptProof{
				Bip86: true,
			}
			exclusionProofs = append(
				exclusionProofs, exclusionProof,
			)

			continue
		}

		_, assetProof, err := tree.Proof(
			split.root.TapCommitmentKey(),
			split.root.AssetCommitmentKey(),
		)
		require.NoError(t, err)

		exclusionProof.CommitmentProof = &CommitmentProof{
			Proof:      *assetProof,
			STXOProofs: stxoProofsFor(t, stxoAssets, tree),
		}
		exclusionProofs = append(exclusionProofs, exclusionProof)
	}

	return &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block:            a.block,
			Tx:               a.tx,
			TxIndex:          0,
			OutputIndex:      int(split.rootOutput),
			InternalKey:      a.internalKeys[split.rootOutput],
			TaprootAssetRoot: a.trees[split.rootOutput],
			ExclusionProofs:  exclusionProofs,
		},
		NewAsset:         split.root,
		RootLocatorProof: &split.locatorProof,
	}
}

// spenderCarrier returns the commitment proof that carries the spender proofs
// of the given proof: the one for the anchor output of the root asset.
func spenderCarrier(p *Proof) *CommitmentProof {
	if p.Asset.HasSplitCommitmentWitness() {
		return p.SplitRootProof.CommitmentProof
	}

	return p.InclusionProof.CommitmentProof
}

// TestSpenderProofs tests that the proofs of the assets of a transfer carry
// the spender proofs for the inputs spent by the root asset, if its anchor
// output commits to the spender leaves, and that those proofs are verified
// whenever they are present.
func TestSpenderProofs(t *testing.T) {
	t.Parallel()

	// The BIP-86 output comes last, as the proof of a root asset signals
	// its STXO proofs by way of its first exclusion proof.
	const (
		rootOutput = iota
		splitOutput
		btcOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)
	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput},
		spenders:     true,
	}
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, genesis.sign, split,
	)

	rootProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.rootParams(t, split),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)
	require.NoError(t, genesis.verify(t, rootProof))
	require.NotNil(
		t, exclusionProofFor(rootProof, btcOutput).TapscriptProof,
	)

	splitProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.splitParams(t, split, 0),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)
	require.NoError(t, genesis.verify(t, splitProof))

	// Only the proof for the anchor output of the root asset carries the
	// spender proofs.
	ownProof := splitProof.InclusionProof.CommitmentProof
	require.Empty(t, ownProof.SpenderProofs)
	for _, p := range []*Proof{rootProof, splitProof} {
		for idx := range p.ExclusionProofs {
			exclusionProof := p.ExclusionProofs[idx]
			if exclusionProof.CommitmentProof == nil {
				continue
			}

			require.Empty(
				t, exclusionProof.CommitmentProof.SpenderProofs,
			)
		}
	}

	spenderAsset, err := asset.MakeSpenderAsset(
		split.root.PrevWitnesses[0], split.root,
	)
	require.NoError(t, err)
	spenderKey := stxoKey(spenderAsset)

	testCases := []struct {
		name        string
		mutate      func(c *CommitmentProof)
		wantErr     error
		wantErrText string
	}{{
		name:   "valid",
		mutate: func(c *CommitmentProof) {},
	}, {
		name: "no spender proofs",
		mutate: func(c *CommitmentProof) {
			c.SpenderProofs = nil
		},
	}, {
		name: "unknown spender key",
		mutate: func(c *CommitmentProof) {
			otherKey := asset.ToSerialized(test.RandPubKey(t))
			c.SpenderProofs[otherKey] = c.SpenderProofs[spenderKey]
		},
		wantErrText: "missing spender asset",
	}, {
		name: "proof of other leaf",
		mutate: func(c *CommitmentProof) {
			for _, stxoProof := range c.STXOProofs {
				c.SpenderProofs[spenderKey] = stxoProof
			}
		},
		wantErr: commitment.ErrInvalidTaprootProof,
	}, {
		name: "exclusion proof",
		mutate: func(c *CommitmentProof) {
			splitTree := anchor.trees[splitOutput]
			_, exclusionProof, err := splitTree.Proof(
				spenderAsset.TapCommitmentKey(),
				spenderAsset.AssetCommitmentKey(),
			)
			require.NoError(t, err)

			c.SpenderProofs[spenderKey] = *exclusionProof
		},
		wantErr: commitment.ErrMissingAssetProof,
	}}

	proofs := map[string]*Proof{
		"root":  rootProof,
		"split": splitProof,
	}
	for proofName, p := range proofs {
		require.Len(t, spenderCarrier(p).SpenderProofs, 1)
		require.Contains(t, spenderCarrier(p).SpenderProofs, spenderKey)

		for _, tc := range testCases {
			t.Run(proofName+"/"+tc.name, func(t *testing.T) {
				// The copy is made by way of the encoding, so
				// the spender proofs are carried across it.
				mutated := copyProof(t, p)
				carrier := spenderCarrier(mutated)
				require.Len(t, carrier.SpenderProofs, 1)
				tc.mutate(carrier)

				err := genesis.verify(t, mutated)
				switch {
				case tc.wantErr != nil:
					require.ErrorIs(t, err, tc.wantErr)

				case tc.wantErrText != "":
					require.ErrorContains(
						t, err, tc.wantErrText,
					)

				default:
					require.NoError(t, err)
				}
			})
		}
	}
}

// TestSpenderProofsAbsent tests that the proofs of a transfer whose anchor
// outputs don't commit to any spender leaves carry no spender proofs.
func TestSpenderProofsAbsent(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		splitOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)
	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput},
	}
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, genesis.sign, split,
	)

	params := []*TransitionParams{
		anchor.rootParams(t, split), anchor.splitParams(t, split, 0),
	}
	for _, p := range params {
		transitionProof, err := CreateTransitionProof(
			genesis.outPoint, p, WithVersion(TransitionV1),
		)
		require.NoError(t, err)
		require.NoError(t, genesis.verify(t, transitionProof))

		require.Empty(t, spenderCarrier(transitionProof).SpenderProofs)
	}
}

// TestSpenderProofsMultiInput tests that the spender proofs of a transfer must
// cover every input spent by its root asset.
func TestSpenderProofsMultiInput(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		splitOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)

	// The second input is an asset of the same kind, anchored elsewhere.
	otherInput := genesis.proof.Asset.Copy()
	otherInput.ScriptKey = asset.NewScriptKey(test.RandPubKey(t))
	inputs := append(genesis.inputs, commitment.SplitCommitmentInput{
		Asset: otherInput,
		OutPoint: wire.OutPoint{
			Hash:  test.RandHash(),
			Index: 1,
		},
	})

	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput},
		spenders:     true,
	}
	anchor := newTestSplitAnchor(t, inputs, numOutputs, nil, split)

	require.Len(t, split.root.PrevWitnesses, 2)
	otherSpender, err := asset.MakeSpenderAsset(
		split.root.PrevWitnesses[1], split.root,
	)
	require.NoError(t, err)

	params := map[string]*TransitionParams{
		"root":  anchor.rootParams(t, split),
		"split": anchor.splitParams(t, split, 0),
	}
	for name, p := range params {
		t.Run(name, func(t *testing.T) {
			transitionProof, err := CreateTransitionProof(
				genesis.outPoint, p, WithVersion(TransitionV1),
			)
			require.NoError(t, err)

			// The root asset isn't signed, so we only verify the
			// inclusion and exclusion proofs.
			_, err = transitionProof.VerifyProofs()
			require.NoError(t, err)

			spenderProofs := spenderCarrier(transitionProof).
				SpenderProofs
			require.Len(t, spenderProofs, 2)
			delete(spenderProofs, stxoKey(otherSpender))

			_, err = transitionProof.VerifyProofs()
			require.ErrorIs(t, err, ErrSpenderProofMissing)
		})
	}
}

// TestSpenderProofsCompetingSplits tests that the spender proofs of a split
// asset can't be satisfied by two splits of the same input whose root assets
// are committed to the same anchor output.
func TestSpenderProofsCompetingSplits(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		splitOutput
		otherSplitOutput
		numOutputs
	)

	// Both root assets share the STXO of the input. The anchor output can
	// only name one of them as its spender.
	genesis := newSplitGenesis(t)
	named := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput},
		spenders:     true,
	}
	other := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{otherSplitOutput},
		noSTXOs:      true,
	}
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, genesis.sign, named, other,
	)

	namedProofs := make(map[string]*Proof)
	for name, params := range map[string]*TransitionParams{
		"root":  anchor.rootParams(t, named),
		"split": anchor.splitParams(t, named, 0),
	} {
		namedProof, err := CreateTransitionProof(
			genesis.outPoint, params, WithVersion(TransitionV1),
		)
		require.NoError(t, err)
		require.NoError(t, genesis.verify(t, namedProof))
		require.Len(t, spenderCarrier(namedProof).SpenderProofs, 1)

		namedProofs[name] = namedProof
	}

	for name, params := range map[string]*TransitionParams{
		"root":  anchor.rootParams(t, other),
		"split": anchor.splitParams(t, other, 0),
	} {
		t.Run(name, func(t *testing.T) {
			// No spender proofs can be generated for the other
			// transfer.
			_, err := CreateTransitionProof(
				genesis.outPoint, params,
				WithVersion(TransitionV1),
			)
			require.ErrorContains(
				t, err, "spender leaf does not name",
			)

			// The only spender proofs there are for the input don't
			// verify for the other transfer either.
			otherProof, err := CreateTransitionProof(
				genesis.outPoint, params, WithNoSTXOProofs(),
			)
			require.NoError(t, err)

			spenderCarrier(otherProof).SpenderProofs =
				spenderCarrier(namedProofs[name]).SpenderProofs

			err = genesis.verify(t, otherProof)
			require.ErrorIs(
				t, err, commitment.ErrInvalidTaprootProof,
			)
			require.ErrorContains(
				t, err, "error verifying spender proof",
			)
		})
	}
}

// TestSpenderProofsCompetingRoots tests that the spender proofs of a full
// value transfer can't be satisfied by two transfers of the same input that
// are committed to the same anchor output.
func TestSpenderProofsCompetingRoots(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		// burn turns the transfer that isn't named as the spender into
		// a burn of the input.
		burn bool
	}{{
		name: "transfers",
	}, {
		name: "burn and transfer",
		burn: true,
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testSpenderProofsCompetingRoots(t, tc.burn)
		})
	}
}

func testSpenderProofsCompetingRoots(t *testing.T, burn bool) {
	amt := uint64(100)
	genesisProof, senderPrivKey := genRandomGenesisWithProof(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil, asset.V0,
	)
	genesisOutPoint := wire.OutPoint{
		Hash:  genesisProof.AnchorTx.TxHash(),
		Index: genesisProof.InclusionProof.OutputIndex,
	}
	prevID := asset.PrevID{
		OutPoint: genesisOutPoint,
		ID:       genesisProof.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			genesisProof.Asset.ScriptKey.PubKey,
		),
	}

	// Each new asset claims the full amount of the same input.
	newScriptKey := func() asset.ScriptKey {
		return asset.NewScriptKeyBip86(
			test.PubToKeyDesc(test.RandPrivKey().PubKey()),
		)
	}
	scriptKeys := []asset.ScriptKey{newScriptKey(), newScriptKey()}
	if burn {
		scriptKeys[1] = asset.NewScriptKey(asset.DeriveBurnKey(prevID))
	}

	newAssets := make([]*asset.Asset, len(scriptKeys))
	for idx := range scriptKeys {
		newAsset := genesisProof.Asset.Copy()
		newAsset.ScriptKey = scriptKeys[idx]
		signAssetTransfer(
			t, &genesisProof, newAsset, senderPrivKey, nil,
		)

		newAssets[idx] = newAsset
	}
	require.Equal(t, burn, newAssets[1].IsBurn())

	// Both assets share the STXO of the input. The anchor output names
	// the first asset as its spender.
	tapCommitment, err := commitment.FromAssets(nil, newAssets...)
	require.NoError(t, err)

	stxoAssets, err := asset.CollectSTXO(newAssets[0])
	require.NoError(t, err)
	spenderAssets, err := asset.CollectSpenders(newAssets[0])
	require.NoError(t, err)
	err = tapCommitment.MergeAltLeaves(append(stxoAssets, spenderAssets...))
	require.NoError(t, err)

	// A second spender of the input has no place in the anchor output.
	otherSpenderAssets, err := asset.CollectSpenders(newAssets[1])
	require.NoError(t, err)
	err = tapCommitment.MergeAltLeaves(otherSpenderAssets)
	require.ErrorIs(t, err, asset.ErrDuplicateAltLeafKey)

	internalKey := test.SchnorrPubKey(t, test.RandPrivKey())
	tapscriptRoot := tapCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)

	chainTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: genesisOutPoint,
		}},
		TxOut: []*wire.TxOut{{
			PkScript: test.ComputeTaprootScript(t, taprootKey),
			Value:    330,
		}},
	}

	// The anchor transaction spends the genesis anchor output for real,
	// and the merkle proofs are verified for real as well.
	genesisCommitment, err := genesisProof.VerifyProofs()
	require.NoError(t, err)
	signAnchorSpend(
		t, chainTx, genesisProof.AnchorTx.TxOut[genesisOutPoint.Index],
		senderPrivKey, genesisCommitment.TapscriptRoot(nil),
	)

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(chainTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	genesisHash := genesisProof.BlockHeader.BlockHash()
	block := &wire.MsgBlock{
		Header: *wire.NewBlockHeader(
			0, &genesisHash, merkleRoot, 0, 0,
		),
		Transactions: []*wire.MsgTx{chainTx},
	}

	params := func(newAsset *asset.Asset) *TransitionParams {
		return &TransitionParams{
			BaseProofParams: BaseProofParams{
				Block:            block,
				Tx:               chainTx,
				TxIndex:          0,
				OutputIndex:      0,
				InternalKey:      internalKey,
				TaprootAssetRoot: tapCommitment,
			},
			NewAsset: newAsset,
		}
	}
	vCtx := MockVerifierCtx
	vCtx.MerkleVerifier = DefaultMerkleVerifier
	verify := func(p *Proof) error {
		f, err := NewFile(V0, genesisProof, *p)
		require.NoError(t, err)

		_, err = f.Verify(t.Context(), vCtx)

		return err
	}

	namedProof, err := CreateTransitionProof(
		genesisOutPoint, params(newAssets[0]),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)
	require.NoError(t, verify(namedProof))
	require.Len(t, spenderCarrier(namedProof).SpenderProofs, 1)

	// No spender proofs can be generated for the other transfer.
	_, err = CreateTransitionProof(
		genesisOutPoint, params(newAssets[1]),
		WithVersion(TransitionV1),
	)
	require.ErrorContains(t, err, "spender leaf does not name")

	// The only spender proofs there are for the input don't verify for
	// the other transfer either.
	otherProof, err := CreateTransitionProof(
		genesisOutPoint, params(newAssets[1]), WithNoSTXOProofs(),
	)
	require.NoError(t, err)

	spenderCarrier(otherProof).SpenderProofs =
		spenderCarrier(namedProof).SpenderProofs

	err = verify(otherProof)
	require.ErrorIs(t, err, commitment.ErrInvalidTaprootProof)
	require.ErrorContains(t, err, "error verifying spender proof")
}

// signAnchorSpend signs the first input of the given transaction, which
// spends the given output by its key path, and executes the spend.
func signAnchorSpend(t *testing.T, tx *wire.MsgTx, prevOut *wire.TxOut,
	internalKey *btcec.PrivateKey, tapscriptRoot chainhash.Hash) {

	t.Helper()

	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)
	sig, err := txscript.RawTxInTaprootSignature(
		tx, sigHashes, 0, prevOut.Value, prevOut.PkScript,
		tapscriptRoot[:], txscript.SigHashDefault, internalKey,
	)
	require.NoError(t, err)
	tx.TxIn[0].Witness = wire.TxWitness{sig}

	engine, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, prevOutFetcher,
	)
	require.NoError(t, err)
	require.NoError(t, engine.Execute())
}

// TestSpenderProofsEncoding tests that the spender proofs of a commitment
// proof are carried across its encoding, and that a decoder that doesn't know
// of them retains them as they are.
func TestSpenderProofsEncoding(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		splitOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)
	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput},
		spenders:     true,
	}
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, genesis.sign, split,
	)

	rootProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.rootParams(t, split),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	commitmentProof := rootProof.InclusionProof.CommitmentProof
	require.Len(t, commitmentProof.SpenderProofs, 1)

	var encoded bytes.Buffer
	require.NoError(t, commitmentProof.Encode(&encoded))

	var decoded CommitmentProof
	err = decoded.Decode(bytes.NewReader(encoded.Bytes()))
	require.NoError(t, err)
	require.Len(t, decoded.SpenderProofs, 1)
	require.Empty(t, decoded.UnknownOddTypes)

	var reEncoded bytes.Buffer
	require.NoError(t, decoded.Encode(&reEncoded))
	require.Equal(t, encoded.Bytes(), reEncoded.Bytes())

	// The record is of an odd type, so a decoder that only knows the
	// records that came before it doesn't reject the proof.
	var (
		legacy      CommitmentProof
		legacyTypes = fn.NewSet(
			commitment.ProofAssetProofType,
			commitment.ProofTaprootAssetProofType,
			CommitmentProofTapSiblingPreimageType,
			CommitmentProofSTXOProofsType,
		)
	)
	records := append(
		legacy.Proof.DecodeRecords(),
		CommitmentProofTapSiblingPreimageRecord(
			&legacy.TapSiblingPreimage,
		),
		CommitmentProofSTXOProofsRecord(&legacy.STXOProofs),
	)
	stream, err := tlv.NewStream(records...)
	require.NoError(t, err)

	legacy.UnknownOddTypes, err = asset.TlvStrictDecodeP2P(
		stream, bytes.NewReader(encoded.Bytes()), legacyTypes,
	)
	require.NoError(t, err)
	require.Contains(
		t, legacy.UnknownOddTypes, CommitmentProofSpenderProofsType,
	)
	require.Len(t, legacy.STXOProofs, 1)
	require.Empty(t, legacy.SpenderProofs)

	reEncoded.Reset()
	require.NoError(t, legacy.Encode(&reEncoded))
	require.Equal(t, encoded.Bytes(), reEncoded.Bytes())
}

// TestSpenderLeavesRebuildCommitment tests that the alt leaves carried by a
// proof rebuild the commitment of its anchor output, if that commits to
// spender leaves.
func TestSpenderLeavesRebuildCommitment(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		splitOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)
	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput},
		spenders:     true,
	}
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, genesis.sign, split,
	)

	rootProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.rootParams(t, split),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	// The STXO and the spender leaf of the single input.
	decoded := copyProof(t, rootProof)
	require.Len(t, decoded.AltLeaves, 2)

	rebuilt, err := commitment.FromAssets(nil, &decoded.Asset)
	require.NoError(t, err)
	require.NoError(t, rebuilt.MergeAltLeaves(decoded.AltLeaves))

	require.Equal(
		t, anchor.trees[rootOutput].TapscriptRoot(nil),
		rebuilt.TapscriptRoot(nil),
	)
}
