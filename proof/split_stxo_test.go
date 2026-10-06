package proof

import (
	"bytes"
	"context"
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
	"github.com/stretchr/testify/require"
)

// testSplit is a split of a set of inputs into a root asset and a number of
// split assets.
type testSplit struct {
	// rootOutput is the index of the anchor output the root asset is
	// committed to.
	rootOutput uint32

	// splitOutputs are the indexes of the anchor outputs the split assets
	// are committed to.
	splitOutputs []uint32

	// noSTXOs leaves the STXOs of the inputs out of the anchor output of
	// the root asset.
	noSTXOs bool

	// spenders commits the spender leaves of the inputs, which name the
	// root asset, to the anchor output of the root asset.
	spenders bool

	root         *asset.Asset
	splits       []*asset.Asset
	locatorProof mssmt.Proof
}

// testSplitAnchor is an anchor transaction that commits to a number of splits.
// Any output that doesn't commit to an asset is a BIP-86 output.
type testSplitAnchor struct {
	block        *wire.MsgBlock
	tx           *wire.MsgTx
	internalKeys map[uint32]*btcec.PublicKey
	trees        map[uint32]*commitment.TapCommitment
}

// newTestSplitAnchor creates the given splits of the inputs, and commits them
// to an anchor transaction with the given number of outputs. The optional
// callback signs the root asset of each split.
func newTestSplitAnchor(t *testing.T, inputs []commitment.SplitCommitmentInput,
	numOutputs uint32, sign func(root *asset.Asset, splits []*asset.Asset),
	splits ...*testSplit) *testSplitAnchor {

	t.Helper()

	var inputAmount uint64
	for idx := range inputs {
		inputAmount += inputs[idx].Asset.Amount
	}

	assetID := inputs[0].Asset.ID()
	assets := make(map[uint32][]*asset.Asset)
	altLeaves := make(map[uint32][]asset.AltLeaf[asset.Asset])
	for _, split := range splits {
		splitAmount := uint64(len(split.splitOutputs))
		rootLocator := &commitment.SplitLocator{
			OutputIndex: split.rootOutput,
			AssetID:     assetID,
			ScriptKey:   asset.ToSerialized(test.RandPubKey(t)),
			Amount:      inputAmount - splitAmount,
		}

		locators := make(
			[]*commitment.SplitLocator, len(split.splitOutputs),
		)
		for idx, outIdx := range split.splitOutputs {
			scriptKey := asset.ToSerialized(test.RandPubKey(t))
			locators[idx] = &commitment.SplitLocator{
				OutputIndex: outIdx,
				AssetID:     assetID,
				ScriptKey:   scriptKey,
				Amount:      1,
			}
		}

		splitCommitment, err := commitment.NewSplitCommitment(
			context.Background(), inputs, rootLocator, locators...,
		)
		require.NoError(t, err)

		splitAssets := splitCommitment.SplitAssets
		split.root = splitCommitment.RootAsset
		split.locatorProof = splitAssets[*rootLocator].
			PrevWitnesses[0].SplitCommitment.Proof
		for _, locator := range locators {
			split.splits = append(
				split.splits, &splitAssets[*locator].Asset,
			)
		}

		if sign != nil {
			sign(split.root, split.splits)
		}

		assets[split.rootOutput] = append(
			assets[split.rootOutput], split.root,
		)
		for idx, outIdx := range split.splitOutputs {
			splitAsset := split.splits[idx].Copy()
			splitAsset.PrevWitnesses[0].SplitCommitment = nil
			assets[outIdx] = append(assets[outIdx], splitAsset)
		}

		if split.spenders {
			spenderAssets, err := asset.CollectSpenders(split.root)
			require.NoError(t, err)
			altLeaves[split.rootOutput] = append(
				altLeaves[split.rootOutput], spenderAssets...,
			)
		}

		if split.noSTXOs {
			continue
		}

		stxoAssets, err := asset.CollectSTXO(split.root)
		require.NoError(t, err)
		altLeaves[split.rootOutput] = append(
			altLeaves[split.rootOutput], stxoAssets...,
		)
	}

	anchor := &testSplitAnchor{
		tx: &wire.MsgTx{
			Version: 2,
		},
		internalKeys: make(map[uint32]*btcec.PublicKey),
		trees:        make(map[uint32]*commitment.TapCommitment),
	}
	for idx := range inputs {
		anchor.tx.TxIn = append(anchor.tx.TxIn, &wire.TxIn{
			PreviousOutPoint: inputs[idx].OutPoint,
		})
	}

	for outIdx := uint32(0); outIdx < numOutputs; outIdx++ {
		internalKey := test.RandPubKey(t)
		anchor.internalKeys[outIdx] = internalKey

		taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
		if outAssets, ok := assets[outIdx]; ok {
			tree, err := commitment.FromAssets(nil, outAssets...)
			require.NoError(t, err)

			err = tree.MergeAltLeaves(altLeaves[outIdx])
			require.NoError(t, err)

			anchor.trees[outIdx] = tree

			tapscriptRoot := tree.TapscriptRoot(nil)
			taprootKey = txscript.ComputeTaprootOutputKey(
				internalKey, tapscriptRoot[:],
			)
		}

		anchor.tx.TxOut = append(anchor.tx.TxOut, &wire.TxOut{
			PkScript: test.ComputeTaprootScript(t, taprootKey),
			Value:    330,
		})
	}

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(anchor.tx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	anchor.block = &wire.MsgBlock{
		Header: *wire.NewBlockHeader(
			0, &inputs[0].OutPoint.Hash, merkleRoot, 0, 0,
		),
		Transactions: []*wire.MsgTx{anchor.tx},
	}

	return anchor
}

// splitParams returns the parameters for the proof of the split asset at the
// given index of the split, including the exclusion proofs for all the other
// outputs of the anchor transaction.
func (a *testSplitAnchor) splitParams(t *testing.T, split *testSplit,
	idx int) *TransitionParams {

	t.Helper()

	splitAsset := split.splits[idx]
	splitOutput := split.splitOutputs[idx]

	stxoAssets, err := asset.CollectSTXO(split.root)
	require.NoError(t, err)

	var exclusionProofs []TaprootProof
	for outIdx := uint32(0); outIdx < uint32(len(a.tx.TxOut)); outIdx++ {
		if outIdx == splitOutput {
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
			splitAsset.TapCommitmentKey(),
			splitAsset.AssetCommitmentKey(),
		)
		require.NoError(t, err)

		exclusionProof.CommitmentProof = &CommitmentProof{
			Proof: *assetProof,
		}

		// The anchor output of the root asset commits to the STXOs, so
		// they are only excluded from the other outputs.
		if outIdx != split.rootOutput {
			exclusionProof.CommitmentProof.STXOProofs =
				stxoProofsFor(t, stxoAssets, tree)
		}

		exclusionProofs = append(exclusionProofs, exclusionProof)
	}

	return &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block:            a.block,
			Tx:               a.tx,
			TxIndex:          0,
			OutputIndex:      int(splitOutput),
			InternalKey:      a.internalKeys[splitOutput],
			TaprootAssetRoot: a.trees[splitOutput],
			ExclusionProofs:  exclusionProofs,
		},
		NewAsset:             splitAsset,
		RootOutputIndex:      split.rootOutput,
		RootInternalKey:      a.internalKeys[split.rootOutput],
		RootTaprootAssetTree: a.trees[split.rootOutput],
		RootLocatorProof:     &split.locatorProof,
	}
}

// stxoProofSet is the set of STXO proofs carried by a commitment proof.
type stxoProofSet = map[asset.SerializedKey]commitment.Proof

// stxoProofsFor returns the proofs for the given STXOs in the given tree.
func stxoProofsFor(t *testing.T, stxoAssets []asset.AltLeaf[asset.Asset],
	tree *commitment.TapCommitment) stxoProofSet {

	t.Helper()

	stxoProofs := make(stxoProofSet)
	for _, stxoLeaf := range stxoAssets {
		stxoAsset := stxoLeaf.(*asset.Asset)
		_, stxoProof, err := tree.Proof(
			stxoAsset.TapCommitmentKey(),
			stxoAsset.AssetCommitmentKey(),
		)
		require.NoError(t, err)

		stxoProofs[stxoKey(stxoAsset)] = *stxoProof
	}

	return stxoProofs
}

// stxoKey returns the key an STXO proof is identified by.
func stxoKey(stxoAsset *asset.Asset) asset.SerializedKey {
	return asset.ToSerialized(stxoAsset.ScriptKey.PubKey)
}

// exclusionProofFor returns the exclusion proof for the given anchor output
// index, or nil if there is none.
func exclusionProofFor(p *Proof, outIdx uint32) *TaprootProof {
	for idx := range p.ExclusionProofs {
		if p.ExclusionProofs[idx].OutputIndex == outIdx {
			return &p.ExclusionProofs[idx]
		}
	}

	return nil
}

// copyProof returns a deep copy of the given proof.
func copyProof(t *testing.T, p *Proof) *Proof {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, p.Encode(&buf))

	var proofCopy Proof
	require.NoError(t, proofCopy.Decode(&buf))

	return &proofCopy
}

// splitGenesis is a minted asset along with all that is needed to split it.
type splitGenesis struct {
	proof    Proof
	outPoint wire.OutPoint
	inputs   []commitment.SplitCommitmentInput
	sign     func(root *asset.Asset, splits []*asset.Asset)
}

// newSplitGenesis mints an asset to be split.
func newSplitGenesis(t *testing.T) *splitGenesis {
	t.Helper()

	amt := uint64(100)
	genesisProof, privKey := genRandomGenesisWithProof(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil, asset.V0,
	)

	g := &splitGenesis{
		proof: genesisProof,
		outPoint: wire.OutPoint{
			Hash:  genesisProof.AnchorTx.TxHash(),
			Index: genesisProof.InclusionProof.OutputIndex,
		},
	}
	g.inputs = []commitment.SplitCommitmentInput{{
		Asset:    &g.proof.Asset,
		OutPoint: g.outPoint,
	}}
	g.sign = func(root *asset.Asset, splits []*asset.Asset) {
		signAssetTransfer(t, &g.proof, root, privKey, splits)
	}

	return g
}

// verify verifies the proof file made of the genesis proof and the given
// transition proof.
func (g *splitGenesis) verify(t *testing.T, p *Proof) error {
	t.Helper()

	f, err := NewFile(V0, g.proof, *p)
	require.NoError(t, err)

	_, err = f.Verify(context.Background(), MockVerifierCtx)

	return err
}

// TestSplitSTXOProofs tests that the proof of a split asset carries the STXO
// proofs for the inputs spent by its root asset, and that those proofs are
// verified whenever they are present.
func TestSplitSTXOProofs(t *testing.T) {
	t.Parallel()

	// The BIP-86 output comes first, so its proof is the first exclusion
	// proof of each split asset.
	const (
		btcOutput = iota
		rootOutput
		splitOutput
		otherSplitOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)
	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput, otherSplitOutput},
	}
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, genesis.sign, split,
	)

	splitProofs := make([]*Proof, len(split.splits))
	for idx := range split.splits {
		splitProof, err := CreateTransitionProof(
			genesis.outPoint, anchor.splitParams(t, split, idx),
			WithVersion(TransitionV1),
		)
		require.NoError(t, err)
		require.NoError(t, genesis.verify(t, splitProof))

		splitProofs[idx] = splitProof
	}

	// The STXO is included in the anchor output of the root asset, and
	// excluded from all the other asset outputs, including the one of the
	// split asset itself.
	splitProof := splitProofs[0]
	rootProof := splitProof.SplitRootProof.CommitmentProof
	ownProof := splitProof.InclusionProof.CommitmentProof
	require.Len(t, rootProof.STXOProofs, 1)
	require.Len(t, ownProof.STXOProofs, 1)

	require.NotNil(
		t, exclusionProofFor(splitProof, btcOutput).TapscriptProof,
	)
	require.Empty(
		t, exclusionProofFor(splitProof, rootOutput).CommitmentProof.
			STXOProofs,
	)
	require.Len(
		t, exclusionProofFor(splitProof, otherSplitOutput).
			CommitmentProof.STXOProofs, 1,
	)

	testCases := []struct {
		name    string
		mutate  func(p *Proof)
		wantErr error
	}{{
		name: "missing exclusion from own output",
		mutate: func(p *Proof) {
			p.InclusionProof.CommitmentProof.STXOProofs = nil
		},
		wantErr: ErrStxoInputProofMissing,
	}, {
		name: "missing exclusion from other output",
		mutate: func(p *Proof) {
			otherProof := exclusionProofFor(p, otherSplitOutput)
			otherProof.CommitmentProof.STXOProofs = nil
		},
		wantErr: ErrStxoInputProofMissing,
	}, {
		name: "invalid inclusion in root output",
		mutate: func(p *Proof) {
			p.SplitRootProof.CommitmentProof.STXOProofs =
				p.InclusionProof.CommitmentProof.STXOProofs
		},
		wantErr: commitment.ErrMissingAssetProof,
	}, {
		name: "invalid exclusion from own output",
		mutate: func(p *Proof) {
			p.InclusionProof.CommitmentProof.STXOProofs =
				p.SplitRootProof.CommitmentProof.STXOProofs
		},
		wantErr: commitment.ErrInvalidTaprootProof,
	}, {
		name: "no STXO proofs",
		mutate: func(p *Proof) {
			p.SplitRootProof.CommitmentProof.STXOProofs = nil
			p.InclusionProof.CommitmentProof.STXOProofs = nil

			otherProof := exclusionProofFor(p, otherSplitOutput)
			otherProof.CommitmentProof.STXOProofs = nil
		},
	}, {
		name: "no STXO proofs for root output",
		mutate: func(p *Proof) {
			p.SplitRootProof.CommitmentProof.STXOProofs = nil
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := copyProof(t, splitProof)
			tc.mutate(mutated)

			err := genesis.verify(t, mutated)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestSplitSTXOProofsSharedOutput tests the STXO proofs of a split asset that
// is committed to the same anchor output as its root asset.
func TestSplitSTXOProofsSharedOutput(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		otherSplitOutput
		btcOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)
	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{rootOutput, otherSplitOutput},
	}
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, genesis.sign, split,
	)

	for idx := range split.splits {
		splitProof, err := CreateTransitionProof(
			genesis.outPoint, anchor.splitParams(t, split, idx),
			WithVersion(TransitionV1),
		)
		require.NoError(t, err)
		require.NoError(t, genesis.verify(t, splitProof))
	}

	// The anchor output of the split asset commits to the STXO, so there is
	// nothing to exclude from it.
	splitProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.splitParams(t, split, 0),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	rootProof := splitProof.SplitRootProof.CommitmentProof
	ownProof := splitProof.InclusionProof.CommitmentProof
	require.Len(t, rootProof.STXOProofs, 1)
	require.Empty(t, ownProof.STXOProofs)
	require.Nil(t, exclusionProofFor(splitProof, rootOutput))

	otherProof := exclusionProofFor(splitProof, otherSplitOutput)
	require.Len(t, otherProof.CommitmentProof.STXOProofs, 1)

	otherProof.CommitmentProof.STXOProofs = nil
	require.ErrorIs(
		t, genesis.verify(t, splitProof), ErrStxoInputProofMissing,
	)
}

// TestSplitSTXOProofsMultiInput tests that the proof of a split asset must
// carry the STXO proofs for every input spent by its root asset.
func TestSplitSTXOProofsMultiInput(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		splitOutput
		otherSplitOutput
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
		splitOutputs: []uint32{splitOutput, otherSplitOutput},
	}
	anchor := newTestSplitAnchor(t, inputs, numOutputs, nil, split)

	splitProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.splitParams(t, split, 0),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	// The root asset isn't signed, so we only verify the inclusion and
	// exclusion proofs.
	_, err = splitProof.VerifyProofs()
	require.NoError(t, err)

	require.Len(t, split.root.PrevWitnesses, 2)
	otherSTXO, err := asset.MakeSpentAsset(split.root.PrevWitnesses[1])
	require.NoError(t, err)

	testCases := []struct {
		name    string
		carrier func(p *Proof) *CommitmentProof
	}{{
		name: "root output",
		carrier: func(p *Proof) *CommitmentProof {
			return p.SplitRootProof.CommitmentProof
		},
	}, {
		name: "own output",
		carrier: func(p *Proof) *CommitmentProof {
			return p.InclusionProof.CommitmentProof
		},
	}, {
		name: "other output",
		carrier: func(p *Proof) *CommitmentProof {
			otherProof := exclusionProofFor(p, otherSplitOutput)
			return otherProof.CommitmentProof
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := copyProof(t, splitProof)

			stxoProofs := tc.carrier(mutated).STXOProofs
			require.Len(t, stxoProofs, 2)
			delete(stxoProofs, stxoKey(otherSTXO))

			_, err := mutated.VerifyProofs()
			require.ErrorIs(t, err, ErrStxoInputProofMissing)
		})
	}
}

// TestSplitSTXOProofsCompetingRoots tests that the STXO proofs of a split
// asset can't be satisfied by two splits of the same input that are
// committed to the same anchor transaction.
func TestSplitSTXOProofsCompetingRoots(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		splitOutput
		otherRootOutput
		otherSplitOutput
		numOutputs
	)

	newSplits := func() []*testSplit {
		return []*testSplit{{
			rootOutput:   rootOutput,
			splitOutputs: []uint32{splitOutput},
		}, {
			rootOutput:   otherRootOutput,
			splitOutputs: []uint32{otherSplitOutput},
		}}
	}

	// If both root outputs commit to the STXO, then neither split asset
	// can prove its exclusion from the root output of the other split.
	t.Run("both roots commit to STXO", func(t *testing.T) {
		genesis := newSplitGenesis(t)
		splits := newSplits()
		anchor := newTestSplitAnchor(
			t, genesis.inputs, numOutputs, genesis.sign, splits...,
		)

		for _, split := range splits {
			splitProof, err := CreateTransitionProof(
				genesis.outPoint,
				anchor.splitParams(t, split, 0),
				WithVersion(TransitionV1),
			)
			require.NoError(t, err)

			require.ErrorIs(
				t, genesis.verify(t, splitProof),
				commitment.ErrInvalidTaprootProof,
			)
		}
	})

	// If only one root output commits to the STXO, then the split asset of
	// the other split can't prove its inclusion.
	t.Run("one root commits to STXO", func(t *testing.T) {
		genesis := newSplitGenesis(t)
		splits := newSplits()
		splits[1].noSTXOs = true
		anchor := newTestSplitAnchor(
			t, genesis.inputs, numOutputs, genesis.sign, splits...,
		)

		splitProof, err := CreateTransitionProof(
			genesis.outPoint, anchor.splitParams(t, splits[0], 0),
			WithVersion(TransitionV1),
		)
		require.NoError(t, err)
		require.NoError(t, genesis.verify(t, splitProof))

		_, err = CreateTransitionProof(
			genesis.outPoint, anchor.splitParams(t, splits[1], 0),
			WithVersion(TransitionV1),
		)
		require.ErrorContains(t, err, "no alt leaves")
	})
}
