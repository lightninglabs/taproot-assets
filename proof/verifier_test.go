package proof

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// createProofConfig is a configuration struct for creating proofs. Not all
// options are available for all proof creation functions.
type createProofConfig struct {
	additionalPrevWitnesses []asset.Witness
	addStxoProof            bool
	addAdditionalStxoProofs bool
	updateAnchorTx          bool
}

type createProofOpt func(*createProofConfig)

func withAdditionalPrevWitnesses(
	additionalPrevWitnesses []asset.Witness) createProofOpt {

	return func(cfg *createProofConfig) {
		cfg.additionalPrevWitnesses = additionalPrevWitnesses
	}
}

func withAddStxoProof() createProofOpt {
	return func(cfg *createProofConfig) {
		cfg.addStxoProof = true
	}
}

func withAddAdditionalStxoProofs() createProofOpt {
	return func(cfg *createProofConfig) {
		cfg.addAdditionalStxoProofs = true
	}
}

func withUpdateAnchorTx() createProofOpt {
	return func(cfg *createProofConfig) {
		cfg.updateAnchorTx = true
	}
}

// outputScript returns the output script for the given taproot commitment
// and internal key.
func outputScript(t *testing.T, c *commitment.TapCommitment,
	i *btcec.PublicKey) []byte {

	tapscriptRoot := c.TapscriptRoot(nil)
	expectedKey, err := schnorr.ParsePubKey(schnorr.SerializePubKey(
		txscript.ComputeTaprootOutputKey(i, tapscriptRoot[:]),
	))
	pkScript, err := txscript.PayToTaprootScript(expectedKey)
	require.NoError(t, err)

	return pkScript
}

// makeSpentAsset creates a random asset that spends the given witness.
func makeSpentAsset(t *testing.T, witness asset.Witness) *asset.Asset {
	prevIdKey := asset.DeriveBurnKey(*witness.PrevID)
	scriptKey := asset.NewScriptKey(prevIdKey)
	spentAsset, err := asset.NewAltLeaf(scriptKey, asset.ScriptV0)
	require.NoError(t, err)

	return spentAsset
}

// makeV0InclusionProof creates a random asset and a v0 inclusion proof for it.
func makeV0InclusionProof(t *testing.T,
	opts ...createProofOpt) (*Proof, *commitment.TapCommitment) {

	cfg := &createProofConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	randAsset := asset.RandAsset(t, asset.Normal)

	// Make sure it's a transfer asset and not a genesis.
	randAsset.PrevWitnesses[0].PrevID.ID = asset.RandID(t)

	for _, w := range cfg.additionalPrevWitnesses {
		randAsset.PrevWitnesses = append(randAsset.PrevWitnesses, w)
	}

	v2 := commitment.TapCommitmentV2
	assetCommitment, err := commitment.NewAssetCommitment(randAsset)
	require.NoError(t, err)
	tapCommitment, err := commitment.NewTapCommitment(&v2, assetCommitment)
	require.NoError(t, err)

	_, v0Proof, err := tapCommitment.Proof(
		randAsset.TapCommitmentKey(), randAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	internalKey := test.RandPubKey(t)

	anchorTx := wire.NewMsgTx(2)
	anchorTx.TxOut = []*wire.TxOut{
		{
			PkScript: outputScript(t, tapCommitment, internalKey),
		},
	}

	return &Proof{
		Asset: *randAsset,
		InclusionProof: TaprootProof{
			InternalKey: internalKey,
			CommitmentProof: &CommitmentProof{
				Proof: *v0Proof,
			},
		},
		AnchorTx: *anchorTx,
	}, tapCommitment
}

// addV1InclusionProof takes the existing v0 inclusion proof and adds the v1
// inclusion proof for the STXO. This modifies the passed commitment and the
// v0 proof, but not the anchor transaction.
func addV1InclusionProof(t *testing.T, p *Proof, c *commitment.TapCommitment,
	opts ...createProofOpt) (commitment.Proof, asset.SerializedKey) {

	cfg := &createProofConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	spentAsset0 := makeSpentAsset(t, p.Asset.PrevWitnesses[0])
	key0 := asset.ToSerialized(spentAsset0.ScriptKey.PubKey)

	stxoCommitment, err := commitment.NewAssetCommitment(spentAsset0)
	require.NoError(t, err)

	err = c.Upsert(stxoCommitment)
	require.NoError(t, err)

	// Before we create proofs, add any additional STXO assets to the
	// commitment.
	if cfg.addAdditionalStxoProofs {
		for i := 1; i < len(p.Asset.PrevWitnesses); i++ {
			spentAsset := makeSpentAsset(
				t, p.Asset.PrevWitnesses[i],
			)

			err := stxoCommitment.Upsert(spentAsset)
			require.NoError(t, err)

			err = c.Upsert(stxoCommitment)
			require.NoError(t, err)
		}
	}

	_, stxoProof0, err := c.Proof(
		asset.EmptyGenesisID, spentAsset0.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	_, v0Proof, err := c.Proof(
		p.Asset.TapCommitmentKey(), p.Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	p.InclusionProof.CommitmentProof.Proof = *v0Proof

	cp := p.InclusionProof.CommitmentProof
	if cfg.addStxoProof {
		cp.STXOProofs = map[asset.SerializedKey]commitment.Proof{
			key0: *stxoProof0,
		}
	}

	if cfg.addAdditionalStxoProofs {
		for i := 1; i < len(p.Asset.PrevWitnesses); i++ {
			spentAsset := makeSpentAsset(
				t, p.Asset.PrevWitnesses[i],
			)
			key := asset.ToSerialized(spentAsset.ScriptKey.PubKey)

			_, stxoProof, err := c.Proof(
				asset.EmptyGenesisID,
				spentAsset.AssetCommitmentKey(),
			)
			require.NoError(t, err)

			cp.STXOProofs[key] = *stxoProof
		}
	}

	if cfg.updateAnchorTx {
		p.AnchorTx.TxOut[0].PkScript = outputScript(
			t, c, p.InclusionProof.InternalKey,
		)
	}

	return *stxoProof0, key0
}

func addV0ExclusionOutput(t *testing.T, p *Proof, c *commitment.TapCommitment,
	tapKey, assetKey [32]byte, internalKey *btcec.PublicKey,
	outputIndex uint32) {

	_, exclusionProof, err := c.Proof(tapKey, assetKey)
	require.NoError(t, err)

	p.AnchorTx.TxOut = append(p.AnchorTx.TxOut, &wire.TxOut{
		PkScript: outputScript(t, c, internalKey),
	})
	p.ExclusionProofs = []TaprootProof{{
		OutputIndex: outputIndex,
		InternalKey: internalKey,
		CommitmentProof: &CommitmentProof{
			Proof: *exclusionProof,
		},
	}}
}

func addV1ExclusionProof(t *testing.T, p *Proof, c *commitment.TapCommitment,
	outputIndex uint32) {

	spentAsset := makeSpentAsset(t, p.Asset.PrevWitnesses[0])
	key := asset.ToSerialized(spentAsset.ScriptKey.PubKey)

	_, stxoExclusionProof, err := c.Proof(
		asset.EmptyGenesisID, spentAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	for idx := range p.ExclusionProofs {
		if p.ExclusionProofs[idx].OutputIndex != outputIndex {
			continue
		}

		cp := p.ExclusionProofs[idx].CommitmentProof
		cp.STXOProofs = map[asset.SerializedKey]commitment.Proof{
			key: *stxoExclusionProof,
		}
	}
}

// TestVerifyV0V1InclusionProofs tests that we properly verify the inclusion
// proofs for both v0 and v1.
func TestVerifyV1InclusionProof(t *testing.T) {
	testCases := []struct {
		name                string
		makeProof           func(t *testing.T) *Proof
		expectedErr         error
		expectedErrContains string
	}{{
		name: "v0 proof with v0 version",
		makeProof: func(t *testing.T) *Proof {
			p, _ := makeV0InclusionProof(t)

			return p
		},
	}, {
		name: "v0 proof with v1 version",
		makeProof: func(t *testing.T) *Proof {
			// If we create a v0 proof but mark it as v1,
			// it should fail to verify.
			p, _ := makeV0InclusionProof(t)
			p.Version = TransitionV1

			return p
		},
		expectedErr: ErrInvalidCommitmentProof,
	}, {
		name: "invalid v0 proof",
		makeProof: func(t *testing.T) *Proof {
			// We create a valid v0 proof, which we tested
			// above is valid on its own.
			p, rootCommitment := makeV0InclusionProof(t)

			// But now we add an STXO asset to the root commitment,
			// which should cause the proof to be invalid, since the
			// root commitment changed, and we don't update the
			// anchor tx output yet.
			_, _ = addV1InclusionProof(
				t, p, rootCommitment, withAddStxoProof(),
			)

			return p
		},
		expectedErrContains: "error verifying v0 inclusion proof",
	}, {
		name: "missing v1 proof",
		makeProof: func(t *testing.T) *Proof {
			p, rootCommitment := makeV0InclusionProof(t)
			p.Version = TransitionV1

			// But now we add an STXO asset to the root commitment,
			// which should cause the proof to be invalid, since the
			// root commitment changed, and we don't update the
			// anchor tx output yet.
			_, _ = addV1InclusionProof(
				t, p, rootCommitment, withUpdateAnchorTx(),
			)

			return p
		},
		expectedErr:         ErrInvalidCommitmentProof,
		expectedErrContains: "missing STXO proofs",
	}, {
		name: "correct v0 and v1 proofs",
		makeProof: func(t *testing.T) *Proof {
			p, rootCommitment := makeV0InclusionProof(t)
			p.Version = TransitionV1

			// We add an STXO asset to the root commitment, and we
			// also update the anchor TX.
			_, _ = addV1InclusionProof(
				t, p, rootCommitment, withAddStxoProof(),
				withUpdateAnchorTx(),
			)

			return p
		},
	}, {
		name: "invalid v1 proof",
		makeProof: func(t *testing.T) *Proof {
			p, rootCommitment := makeV0InclusionProof(t)
			p.Version = TransitionV1

			// We add an STXO asset to the root commitment.
			_, key := addV1InclusionProof(
				t, p, rootCommitment, withAddStxoProof(),
				withUpdateAnchorTx(),
			)

			// At this point both proofs are valid. But we want to
			// invalidate just the v1 proof, so we replace it by one
			// that is derived from a different commitment. We can
			// achieve that by downgrading the commitment and
			// re-deriving the same proof, without updating the
			// anchor output transaction.
			clonedCommitment, err := rootCommitment.Downgrade()
			require.NoError(t, err)

			_, v1ProofOld, err := clonedCommitment.Proof(
				asset.EmptyGenesisID,
				p.Asset.AssetCommitmentKey(),
			)
			require.NoError(t, err)

			cp := p.InclusionProof.CommitmentProof
			cp.STXOProofs[key] = *v1ProofOld

			return p
		},
		expectedErrContains: "error verifying STXO proof: invalid " +
			"taproot proof",
	}, {
		name: "stxo proof missing",
		makeProof: func(t *testing.T) *Proof {
			// We create a proof for an asset that spends two
			// inputs.
			moreInputs := []asset.Witness{{
				PrevID: &asset.PrevID{
					ID: asset.RandID(t),
				},
			}}
			p, rootCommitment := makeV0InclusionProof(
				t, withAdditionalPrevWitnesses(moreInputs),
			)
			p.Version = TransitionV1

			// We add the first STXO asset to the root commitment.
			// The second one is missing, so the proof should be
			// invalid.
			_, _ = addV1InclusionProof(
				t, p, rootCommitment, withAddStxoProof(),
				withUpdateAnchorTx(),
			)

			return p
		},
		expectedErr:         ErrInvalidCommitmentProof,
		expectedErrContains: "missing inclusion proof",
	}, {
		name: "multiple valid stxo proofs",
		makeProof: func(t *testing.T) *Proof {
			// We create a proof for an asset that spends two
			// inputs.
			moreInputs := []asset.Witness{{
				PrevID: &asset.PrevID{
					ID: asset.RandID(t),
				},
			}}
			p, rootCommitment := makeV0InclusionProof(
				t, withAdditionalPrevWitnesses(moreInputs),
			)
			p.Version = TransitionV1

			// We add the first STXO asset to the root commitment.
			// The second one is missing, so the proof should be
			// invalid.
			_, _ = addV1InclusionProof(
				t, p, rootCommitment, withAddStxoProof(),
				withAddAdditionalStxoProofs(),
				withUpdateAnchorTx(),
			)

			return p
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.makeProof(t)
			_, err := p.verifyInclusionProof()

			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)

				// In case we want to also check for a specific
				// error message, we can do that here.
				require.ErrorContains(
					t, err, tc.expectedErrContains,
				)

				return

			}

			if tc.expectedErrContains != "" {
				require.ErrorContains(
					t, err, tc.expectedErrContains,
				)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestVerifyV1ExclusionProof tests that we properly verify the exclusion
// proofs for v1.
func TestVerifyV1ExclusionProof(t *testing.T) {
	internalKey := test.RandPubKey(t)
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	dummyP2TR, err := txscript.PayToTaprootScript(taprootKey)
	require.NoError(t, err)

	testCases := []struct {
		name                string
		makeProof           func(t *testing.T) *Proof
		expectedErr         error
		expectedErrContains string
	}{{
		name: "no proof to verify",
		makeProof: func(t *testing.T) *Proof {
			p := &Proof{
				InclusionProof: TaprootProof{
					OutputIndex: 2,
				},
				ExclusionProofs: []TaprootProof{{
					OutputIndex: 1,
					InternalKey: internalKey,
					TapscriptProof: &TapscriptProof{
						Bip86: true,
					},
				}},
				AnchorTx: wire.MsgTx{
					TxOut: []*wire.TxOut{{
						// Non-P2TR output.
						PkScript: []byte{0x1, 0x2},
					}, {
						// Tapscript output.
						PkScript: dummyP2TR,
					}, {
						// The output with the inclusion
						// proof.
						PkScript: dummyP2TR,
					}},
				},
			}

			return p
		},
	}, {
		name: "missing v0 exclusion proof",
		makeProof: func(t *testing.T) *Proof {
			p, rootCommitment := makeV0InclusionProof(t)

			// We prove the non-existence of a random value.
			addV0ExclusionOutput(
				t, p, rootCommitment, test.RandHash(),
				test.RandHash(), internalKey, 1,
			)

			return p
		},
		expectedErrContains: "error verifying exclusion proof",
	}, {
		name: "correct v0 exclusion proof",
		makeProof: func(t *testing.T) *Proof {
			p, _ := makeV0InclusionProof(t)

			// We now correctly prove that the asset isn't in the
			// second output.
			emptyCommitment, err := commitment.NewTapCommitment(nil)
			require.NoError(t, err)

			addV0ExclusionOutput(
				t, p, emptyCommitment,
				p.Asset.TapCommitmentKey(),
				p.Asset.AssetCommitmentKey(), internalKey, 1,
			)

			return p
		},
	}, {
		name: "missing v1 exclusion proof",
		makeProof: func(t *testing.T) *Proof {
			p, _ := makeV0InclusionProof(t)

			// We now correctly prove that the asset isn't in the
			// second output.
			emptyCommitment, err := commitment.NewTapCommitment(nil)
			require.NoError(t, err)

			addV0ExclusionOutput(
				t, p, emptyCommitment,
				p.Asset.TapCommitmentKey(),
				p.Asset.AssetCommitmentKey(), internalKey, 1,
			)

			// We set the proof's version to V1, so we would require
			// an STXO proof, but don't supply one.
			p.Version = TransitionV1

			return p
		},
		expectedErr:         ErrInvalidCommitmentProof,
		expectedErrContains: "missing STXO proofs",
	}, {
		name: "correct v1 exclusion proof",
		makeProof: func(t *testing.T) *Proof {
			p, _ := makeV0InclusionProof(t)

			// We now correctly prove that the asset isn't in the
			// second output.
			emptyCommitment, err := commitment.NewTapCommitment(nil)
			require.NoError(t, err)

			addV0ExclusionOutput(
				t, p, emptyCommitment,
				p.Asset.TapCommitmentKey(),
				p.Asset.AssetCommitmentKey(), internalKey, 1,
			)

			addV1ExclusionProof(t, p, emptyCommitment, 1)

			// We now have a V1 proof, so we expect the proof to
			// verify successfully.
			p.Version = TransitionV1

			return p
		},
	}, {
		name: "multiple assets with an exclusion proof each",
		makeProof: func(t *testing.T) *Proof {
			// TODO(guggero): implement
			return nil
		},
	}, {
		name: "multiple outputs, multiple assets, one exclusion " +
			"proof missing",
		makeProof: func(t *testing.T) *Proof {
			// TODO(guggero): implement
			return nil
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.makeProof(t)
			_, err := p.verifyExclusionProofs()

			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)

				// In case we want to also check for a specific
				// error message, we can do that here.
				require.ErrorContains(
					t, err, tc.expectedErrContains,
				)

				return

			}

			if tc.expectedErrContains != "" {
				require.ErrorContains(
					t, err, tc.expectedErrContains,
				)

				return
			}

			require.NoError(t, err)
		})
	}
}
