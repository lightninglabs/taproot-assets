package tapgarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type customAnchorRepairTestStore struct {
	candidates []CustomAnchorKeyRepairCandidate
	repairErr  error
	repairs    int
}

func (s *customAnchorRepairTestStore) FetchCustomAnchorKeyRepairCandidates(
	context.Context) ([]CustomAnchorKeyRepairCandidate, error) {

	return append([]CustomAnchorKeyRepairCandidate(nil), s.candidates...), nil
}

func (s *customAnchorRepairTestStore) RepairCustomAnchorInternalKey(
	_ context.Context, candidate CustomAnchorKeyRepairCandidate,
	desc keychain.KeyDescriptor) error {

	if s.repairErr != nil {
		return s.repairErr
	}

	for idx := range s.candidates {
		stored := &s.candidates[idx]
		if !bytes.Equal(stored.BatchKey, candidate.BatchKey) ||
			!bytes.Equal(stored.Outpoint, candidate.Outpoint) ||
			stored.AssetOutputIndex != candidate.AssetOutputIndex ||
			!bytes.Equal(stored.ManagedInternalKey, candidate.BatchKey) {

			continue
		}

		stored.ManagedInternalKey = desc.PubKey.SerializeCompressed()
		s.repairs++
		return nil
	}

	return errors.New("repair compare-and-swap failed")
}

type customAnchorRepairTestKeyRing struct {
	keys map[keychain.KeyLocator]*btcec.PublicKey
}

func (k *customAnchorRepairTestKeyRing) DeriveNextKey(context.Context,
	keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	return keychain.KeyDescriptor{}, errors.New("not implemented")
}

func (k *customAnchorRepairTestKeyRing) IsLocalKey(_ context.Context,
	desc keychain.KeyDescriptor) bool {

	pubKey, ok := k.keys[desc.KeyLocator]
	return ok && pubKey.IsEqual(desc.PubKey)
}

func (k *customAnchorRepairTestKeyRing) DeriveSharedKey(context.Context,
	*btcec.PublicKey, *keychain.KeyLocator) ([sha256.Size]byte, error) {

	return [sha256.Size]byte{}, errors.New("not implemented")
}

func customAnchorRepairCandidate(t *testing.T) (
	CustomAnchorKeyRepairCandidate, keychain.KeyDescriptor) {

	t.Helper()

	batchKey, _ := test.RandKeyDesc(t)
	anchorKey, _ := test.RandKeyDesc(t)
	anchorKey.Family = asset.TaprootAssetsKeyFamily
	anchorKey.Index = 721
	merkleRoot := test.RandBytes(32)

	outputKey := txscript.ComputeTaprootOutputKey(
		anchorKey.PubKey, merkleRoot,
	)
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	prevHash := chainhash.Hash(test.RandBytes(32))
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: prevHash, Index: 3,
	}})
	tx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: pkScript})

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	// Historical managed UTXO rows exist only after the signed packet was
	// committed. A zero-item witness is sufficient for PSBT extraction in
	// this storage-level fixture; script validity isn't part of this audit.
	packet.Inputs[0].FinalScriptWitness = []byte{0}
	packet.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
		anchorKey.PubKey,
	)
	bip32, taprootBip32 := tappsbt.Bip32DerivationFromKeyDesc(
		anchorKey, address.TestNet3Tap.HDCoinType,
	)
	packet.Outputs[0].Bip32Derivation = []*psbt.Bip32Derivation{bip32}
	packet.Outputs[0].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{taprootBip32}
	packet.Unknowns = []*psbt.Unknown{{
		Key:   append([]byte(nil), customAnchorPsbtMarker...),
		Value: []byte{1},
	}}

	var packetBytes bytes.Buffer
	require.NoError(t, packet.Serialize(&packetBytes))

	outpoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	rawOutpoint := make([]byte, 36)
	copy(rawOutpoint[:32], outpoint.Hash[:])
	binary.LittleEndian.PutUint32(rawOutpoint[32:], outpoint.Index)

	return CustomAnchorKeyRepairCandidate{
		BatchKey:           batchKey.PubKey.SerializeCompressed(),
		MintingTxPsbt:      packetBytes.Bytes(),
		AssetOutputIndex:   0,
		Outpoint:           rawOutpoint,
		ManagedInternalKey: batchKey.PubKey.SerializeCompressed(),
		MerkleRoot:         merkleRoot,
	}, anchorKey
}

func mutateRepairPacket(t *testing.T,
	candidate *CustomAnchorKeyRepairCandidate, mutate func(*psbt.Packet)) {

	t.Helper()

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(candidate.MintingTxPsbt), false,
	)
	require.NoError(t, err)
	mutate(packet)

	var packetBytes bytes.Buffer
	require.NoError(t, packet.Serialize(&packetBytes))
	candidate.MintingTxPsbt = packetBytes.Bytes()
}

func TestCustomAnchorHistoricalKeyRepair(t *testing.T) {
	candidate, anchorKey := customAnchorRepairCandidate(t)
	store := &customAnchorRepairTestStore{
		candidates: []CustomAnchorKeyRepairCandidate{candidate},
	}
	keyRing := &customAnchorRepairTestKeyRing{
		keys: map[keychain.KeyLocator]*btcec.PublicKey{
			anchorKey.KeyLocator: anchorKey.PubKey,
		},
	}

	results, err := AuditAndRepairCustomAnchorKeys(
		t.Context(), store, keyRing, address.TestNet3Tap,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, CustomAnchorKeyRepaired, results[0].Status)
	require.False(t, results[0].RequiresIntervention())
	require.Equal(t, 1, store.repairs)
	require.Equal(
		t, anchorKey.PubKey.SerializeCompressed(),
		store.candidates[0].ManagedInternalKey,
	)

	// Replaying the startup audit is a no-op after the successful repair.
	results, err = AuditAndRepairCustomAnchorKeys(
		t.Context(), store, keyRing, address.TestNet3Tap,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, CustomAnchorKeyHealthy, results[0].Status)
	require.Equal(t, 1, store.repairs)
	require.NoError(t, CustomAnchorKeyInterventionError(results))
}

func TestCustomAnchorHistoricalKeyRepairIgnoresSiblingManagedOutput(
	t *testing.T) {

	target, anchorKey := customAnchorRepairCandidate(t)
	mutateRepairPacket(t, &target, func(packet *psbt.Packet) {
		packet.UnsignedTx.TxOut = append(packet.UnsignedTx.TxOut, &wire.TxOut{
			Value:    330,
			PkScript: []byte{txscript.OP_TRUE},
		})
		packet.Outputs = append(packet.Outputs, psbt.POutput{})
	})
	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(target.MintingTxPsbt), false,
	)
	require.NoError(t, err)
	finalTx, err := psbt.Extract(packet)
	require.NoError(t, err)
	hash := finalTx.TxHash()
	copy(target.Outpoint[:32], hash[:])

	sibling := target
	sibling.Outpoint = append([]byte(nil), target.Outpoint...)
	binary.LittleEndian.PutUint32(sibling.Outpoint[32:], 1)
	thirdKey, _ := test.RandKeyDesc(t)
	sibling.ManagedInternalKey = thirdKey.PubKey.SerializeCompressed()

	store := &customAnchorRepairTestStore{
		candidates: []CustomAnchorKeyRepairCandidate{sibling, target},
	}
	results, err := AuditAndRepairCustomAnchorKeys(
		t.Context(), store, localRepairKeyRing(anchorKey),
		address.TestNet3Tap,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, CustomAnchorKeyRepaired, results[0].Status)
	require.Equal(t, 1, store.repairs)
	require.Equal(
		t, thirdKey.PubKey.SerializeCompressed(),
		store.candidates[0].ManagedInternalKey,
	)
}

func TestCustomAnchorHistoricalKeyRepairHealthAttachedToList(t *testing.T) {
	affectedKey, _ := test.RandKeyDesc(t)
	healthyKey, _ := test.RandKeyDesc(t)
	want := "status=key_locator_required: wallet-validated recovery required"

	planter := NewChainPlanter(PlanterConfig{})
	planter.customAnchorKeyErrors[asset.ToSerialized(affectedKey.PubKey)] = want
	batches := []*VerboseBatch{
		{
			MintingBatch: &MintingBatch{BatchKey: affectedKey},
		},
		{
			MintingBatch: &MintingBatch{BatchKey: healthyKey},
		},
	}

	planter.attachCustomAnchorKeyErrors(batches)
	require.Equal(t, want, batches[0].CustomAnchorKeyError)
	require.Empty(t, batches[1].CustomAnchorKeyError)
	require.Equal(t, want, batches[0].Copy().CustomAnchorKeyError)
}

func TestCustomAnchorHistoricalKeyRepairUsesFinalTxID(t *testing.T) {
	candidate, anchorKey := customAnchorRepairCandidate(t)
	mutateRepairPacket(t, &candidate, func(packet *psbt.Packet) {
		// A finalized legacy input can change txid through scriptSig. The
		// repair must bind the stored outpoint to the extracted transaction,
		// not the PSBT's unsigned-transaction hash.
		packet.Inputs[0].FinalScriptWitness = nil
		packet.Inputs[0].FinalScriptSig = []byte{txscript.OP_TRUE}
	})
	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(candidate.MintingTxPsbt), false,
	)
	require.NoError(t, err)
	finalTx, err := psbt.Extract(packet)
	require.NoError(t, err)
	finalHash := finalTx.TxHash()
	require.NotEqual(t, packet.UnsignedTx.TxHash(), finalHash)
	copy(candidate.Outpoint[:32], finalHash[:])

	result, store := auditRepairCandidate(
		t, candidate, anchorKey, true,
	)
	require.Equal(t, CustomAnchorKeyRepaired, result.Status)
	require.Equal(t, 1, store.repairs)
}

func TestCustomAnchorHistoricalKeyRepairRefusals(t *testing.T) {
	t.Run("raw key only", func(t *testing.T) {
		candidate, anchorKey := customAnchorRepairCandidate(t)
		mutateRepairPacket(t, &candidate, func(packet *psbt.Packet) {
			packet.Outputs[0].Bip32Derivation = nil
			packet.Outputs[0].TaprootBip32Derivation = nil
		})

		result, store := auditRepairCandidate(
			t, candidate, anchorKey, true,
		)
		require.Equal(t, CustomAnchorKeyLocatorRequired, result.Status)
		require.Contains(t, result.Detail, "automatic repair is unavailable")
		require.NotContains(t, result.Detail, "supply")
		require.Zero(t, store.repairs)
		assertRepairHealthError(t, result)
	})

	t.Run("non local locator", func(t *testing.T) {
		candidate, anchorKey := customAnchorRepairCandidate(t)
		result, store := auditRepairCandidate(
			t, candidate, anchorKey, false,
		)
		require.Equal(t, CustomAnchorKeyNotLocal, result.Status)
		require.Zero(t, store.repairs)
		assertRepairHealthError(t, result)
	})

	t.Run("already rebound but locator is non local", func(t *testing.T) {
		candidate, anchorKey := customAnchorRepairCandidate(t)
		candidate.ManagedInternalKey = anchorKey.PubKey.SerializeCompressed()

		result, store := auditRepairCandidate(
			t, candidate, anchorKey, false,
		)
		require.Equal(t, CustomAnchorKeyNotLocal, result.Status)
		require.Zero(t, store.repairs)
	})

	t.Run("third persisted key", func(t *testing.T) {
		candidate, anchorKey := customAnchorRepairCandidate(t)
		thirdKey, _ := test.RandKeyDesc(t)
		candidate.ManagedInternalKey = thirdKey.PubKey.SerializeCompressed()

		result, store := auditRepairCandidate(
			t, candidate, anchorKey, true,
		)
		require.Equal(t, CustomAnchorKeyConflict, result.Status)
		require.Zero(t, store.repairs)
	})

	t.Run("compare and swap conflict", func(t *testing.T) {
		candidate, anchorKey := customAnchorRepairCandidate(t)
		store := &customAnchorRepairTestStore{
			candidates: []CustomAnchorKeyRepairCandidate{candidate},
			repairErr:  errors.New("injected CAS conflict"),
		}
		keyRing := localRepairKeyRing(anchorKey)

		results, err := AuditAndRepairCustomAnchorKeys(
			t.Context(), store, keyRing, address.TestNet3Tap,
		)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Equal(t, CustomAnchorKeyConflict, results[0].Status)
		require.Contains(t, results[0].Detail, "injected CAS conflict")
		require.Zero(t, store.repairs)
	})
}

func TestCustomAnchorHistoricalKeyRepairBindingChecks(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*testing.T, *CustomAnchorKeyRepairCandidate)
		relevant   bool
		wantStatus CustomAnchorKeyRepairStatus
	}{
		{
			name: "wrong marker value",
			mutate: func(t *testing.T,
				candidate *CustomAnchorKeyRepairCandidate) {

				mutateRepairPacket(t, candidate, func(packet *psbt.Packet) {
					packet.Unknowns[0].Value = []byte{2}
				})
			},
			relevant: false,
		},
		{
			name: "wrong output index",
			mutate: func(_ *testing.T,
				candidate *CustomAnchorKeyRepairCandidate) {

				candidate.AssetOutputIndex = 1
			},
			relevant:   true,
			wantStatus: CustomAnchorKeyInvalid,
		},
		{
			name: "wrong outpoint txid",
			mutate: func(_ *testing.T,
				candidate *CustomAnchorKeyRepairCandidate) {

				candidate.Outpoint[0] ^= 1
			},
			relevant:   true,
			wantStatus: CustomAnchorKeyInvalid,
		},
		{
			name: "wrong outpoint index",
			mutate: func(_ *testing.T,
				candidate *CustomAnchorKeyRepairCandidate) {

				binary.LittleEndian.PutUint32(candidate.Outpoint[32:], 1)
			},
			relevant: false,
		},
		{
			name: "wrong output script",
			mutate: func(t *testing.T,
				candidate *CustomAnchorKeyRepairCandidate) {

				mutateRepairPacket(t, candidate, func(packet *psbt.Packet) {
					packet.UnsignedTx.TxOut[0].PkScript[2] ^= 1
				})
				packet, err := psbt.NewFromRawBytes(
					bytes.NewReader(candidate.MintingTxPsbt), false,
				)
				require.NoError(t, err)
				hash := packet.UnsignedTx.TxHash()
				copy(candidate.Outpoint[:32], hash[:])
			},
			relevant:   true,
			wantStatus: CustomAnchorKeyInvalid,
		},
		{
			name: "wrong network locator",
			mutate: func(t *testing.T,
				candidate *CustomAnchorKeyRepairCandidate) {

				mutateRepairPacket(t, candidate, func(packet *psbt.Packet) {
					packet.Outputs[0].Bip32Derivation[0].Bip32Path[1] = 0
				})
			},
			relevant:   true,
			wantStatus: CustomAnchorKeyInvalid,
		},
		{
			name: "multiple wallet locators",
			mutate: func(t *testing.T,
				candidate *CustomAnchorKeyRepairCandidate) {

				otherKey, _ := test.RandKeyDesc(t)
				mutateRepairPacket(t, candidate, func(packet *psbt.Packet) {
					derivation := *packet.Outputs[0].Bip32Derivation[0]
					derivation.PubKey = otherKey.PubKey.SerializeCompressed()
					packet.Outputs[0].Bip32Derivation = append(
						packet.Outputs[0].Bip32Derivation, &derivation,
					)
				})
			},
			relevant:   true,
			wantStatus: CustomAnchorKeyInvalid,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			candidate, anchorKey := customAnchorRepairCandidate(t)
			testCase.mutate(t, &candidate)
			store := &customAnchorRepairTestStore{
				candidates: []CustomAnchorKeyRepairCandidate{candidate},
			}
			results, err := AuditAndRepairCustomAnchorKeys(
				t.Context(), store, localRepairKeyRing(anchorKey),
				address.TestNet3Tap,
			)
			require.NoError(t, err)
			if !testCase.relevant {
				require.Empty(t, results)
			} else {
				require.Len(t, results, 1)
				require.Equal(t, testCase.wantStatus,
					results[0].Status)
			}
			require.Zero(t, store.repairs)
		})
	}
}

func auditRepairCandidate(t *testing.T,
	candidate CustomAnchorKeyRepairCandidate, anchorKey keychain.KeyDescriptor,
	local bool) (CustomAnchorKeyRepairHealth, *customAnchorRepairTestStore) {

	t.Helper()

	store := &customAnchorRepairTestStore{
		candidates: []CustomAnchorKeyRepairCandidate{candidate},
	}
	keyRing := &customAnchorRepairTestKeyRing{
		keys: make(map[keychain.KeyLocator]*btcec.PublicKey),
	}
	if local {
		keyRing.keys[anchorKey.KeyLocator] = anchorKey.PubKey
	}

	results, err := AuditAndRepairCustomAnchorKeys(
		t.Context(), store, keyRing, address.TestNet3Tap,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	return results[0], store
}

func localRepairKeyRing(
	desc keychain.KeyDescriptor) *customAnchorRepairTestKeyRing {

	return &customAnchorRepairTestKeyRing{
		keys: map[keychain.KeyLocator]*btcec.PublicKey{
			desc.KeyLocator: desc.PubKey,
		},
	}
}

func assertRepairHealthError(t *testing.T,
	result CustomAnchorKeyRepairHealth) {

	t.Helper()

	err := CustomAnchorKeyInterventionError(
		[]CustomAnchorKeyRepairHealth{result},
	)
	var healthErr *CustomAnchorKeyHealthError
	require.ErrorAs(t, err, &healthErr)
	require.Len(t, healthErr.Results, 1)
	require.Contains(t, fmt.Sprint(err), result.Status.String())
}
