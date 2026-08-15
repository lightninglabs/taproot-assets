package tapgarden

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/keychain"
)

// CustomAnchorKeyRepairStatus describes the result of auditing one historical
// custom mint anchor.
type CustomAnchorKeyRepairStatus uint8

const (
	// CustomAnchorKeyRepaired means the poisoned managed UTXO was repaired
	// with a descriptor proven to belong to the backing wallet.
	CustomAnchorKeyRepaired CustomAnchorKeyRepairStatus = iota

	// CustomAnchorKeyHealthy means the managed UTXO no longer points at the
	// incorrect batch key and already uses the retained anchor key.
	CustomAnchorKeyHealthy

	// CustomAnchorKeyLocatorRequired means the retained packet proves the
	// raw anchor key, but doesn't retain a key locator that can be verified.
	CustomAnchorKeyLocatorRequired

	// CustomAnchorKeyNotLocal means the retained descriptor doesn't derive
	// to a key controlled by the backing wallet.
	CustomAnchorKeyNotLocal

	// CustomAnchorKeyConflict means persisted state changed concurrently or
	// points at a third key, so the repair cannot safely choose a winner.
	CustomAnchorKeyConflict

	// CustomAnchorKeyInvalid means the retained custom-anchor state doesn't
	// satisfy the structural or on-chain binding checks required for repair.
	CustomAnchorKeyInvalid
)

// String returns a stable operator-facing name for a repair status.
func (s CustomAnchorKeyRepairStatus) String() string {
	switch s {
	case CustomAnchorKeyRepaired:
		return "repaired"
	case CustomAnchorKeyHealthy:
		return "healthy"
	case CustomAnchorKeyLocatorRequired:
		return "key_locator_required"
	case CustomAnchorKeyNotLocal:
		return "key_not_local"
	case CustomAnchorKeyConflict:
		return "persisted_key_conflict"
	case CustomAnchorKeyInvalid:
		return "invalid_retained_state"
	default:
		return "unknown"
	}
}

// CustomAnchorKeyRepairHealth is the typed, actionable result for one
// historical custom mint anchor. Detail is safe to surface to an operator and
// never contains private key material.
type CustomAnchorKeyRepairHealth struct {
	Status            CustomAnchorKeyRepairStatus
	BatchKey          []byte
	Outpoint          wire.OutPoint
	AnchorInternalKey []byte
	Detail            string
}

// RequiresIntervention reports whether an operator must supply or reconcile
// key information before tapd can safely spend the historical output.
func (h CustomAnchorKeyRepairHealth) RequiresIntervention() bool {
	return h.Status != CustomAnchorKeyRepaired &&
		h.Status != CustomAnchorKeyHealthy
}

// CustomAnchorKeyHealthError lets readiness and future operator-facing APIs
// promote typed unhealthy audit results to an error without losing detail.
type CustomAnchorKeyHealthError struct {
	Results []CustomAnchorKeyRepairHealth
}

// Error implements error.
func (e *CustomAnchorKeyHealthError) Error() string {
	if len(e.Results) == 0 {
		return "historical custom anchor key health check failed"
	}

	first := e.Results[0]
	return fmt.Sprintf("historical custom anchor key requires operator "+
		"action (status=%s, batch_key=%x, outpoint=%v): %s",
		first.Status, first.BatchKey, first.Outpoint, first.Detail)
}

// CustomAnchorKeyInterventionError returns a typed aggregate error when any
// audit result requires operator action.
func CustomAnchorKeyInterventionError(
	results []CustomAnchorKeyRepairHealth) error {
	issues := make([]CustomAnchorKeyRepairHealth, 0, len(results))
	for _, result := range results {
		if result.RequiresIntervention() {
			issues = append(issues, result)
		}
	}
	if len(issues) == 0 {
		return nil
	}

	return &CustomAnchorKeyHealthError{Results: issues}
}

// AuditAndRepairCustomAnchorKeys audits historical custom-anchor managed UTXO
// rows and repairs only rows whose retained wallet descriptor, transaction and
// output script all agree. Rows lacking a provably local descriptor are
// returned as typed health results and are never mutated.
func AuditAndRepairCustomAnchorKeys(ctx context.Context,
	store CustomAnchorKeyRepairStore, keyRing tapnode.KeyRing,
	chainParams address.ChainParams) ([]CustomAnchorKeyRepairHealth, error) {

	candidates, err := store.FetchCustomAnchorKeyRepairCandidates(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch historical custom anchor "+
			"key candidates: %w", err)
	}

	results := make([]CustomAnchorKeyRepairHealth, 0, len(candidates))
	for _, candidate := range candidates {
		result, desc, relevant := auditCustomAnchorKeyCandidate(
			ctx, candidate, keyRing, chainParams,
		)
		if !relevant {
			continue
		}

		if result.Status == CustomAnchorKeyHealthy ||
			result.RequiresIntervention() {

			results = append(results, result)
			continue
		}

		err := store.RepairCustomAnchorInternalKey(
			ctx, candidate, desc,
		)
		if err != nil {
			result.Status = CustomAnchorKeyConflict
			result.Detail = fmt.Sprintf("verified repair compare-and-swap "+
				"failed: %v", err)
			results = append(results, result)
			continue
		}

		result.Status = CustomAnchorKeyRepaired
		result.Detail = "managed UTXO now references the wallet-verified " +
			"custom anchor key"
		results = append(results, result)
	}

	return results, nil
}

// auditCustomAnchorKeyCandidate proves whether a candidate is relevant and
// safe to repair. A zero status with a non-nil descriptor is the internal
// repairable state; it isn't exposed to callers.
func auditCustomAnchorKeyCandidate(ctx context.Context,
	candidate CustomAnchorKeyRepairCandidate, keyRing tapnode.KeyRing,
	chainParams address.ChainParams) (
	CustomAnchorKeyRepairHealth, keychain.KeyDescriptor, bool) {

	var (
		zeroDesc keychain.KeyDescriptor
		result   = CustomAnchorKeyRepairHealth{
			BatchKey: append([]byte(nil), candidate.BatchKey...),
		}
	)

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(candidate.MintingTxPsbt), false,
	)
	if err != nil {
		// A non-custom row is expected in the broad store query. Without a
		// parseable exact marker, it isn't a historical repair candidate.
		return result, zeroDesc, false
	}
	if !hasExactHistoricalCustomAnchorMarker(packet) {
		return result, zeroDesc, false
	}

	invalid := func(detail string) (CustomAnchorKeyRepairHealth,
		keychain.KeyDescriptor, bool) {

		result.Status = CustomAnchorKeyInvalid
		result.Detail = detail
		return result, zeroDesc, true
	}

	outpoint, err := decodeCustomAnchorRepairOutpoint(candidate.Outpoint)
	if err != nil {
		return invalid(fmt.Sprintf("invalid retained outpoint: %v", err))
	}
	result.Outpoint = outpoint

	finalTx, err := psbt.Extract(packet)
	if err != nil {
		return invalid(fmt.Sprintf("unable to extract retained signed mint "+
			"transaction: %v", err))
	}
	if finalTx == nil ||
		uint64(candidate.AssetOutputIndex) >=
			uint64(len(finalTx.TxOut)) ||
		uint64(candidate.AssetOutputIndex) >= uint64(len(packet.Outputs)) {

		return invalid("retained asset output index is out of range")
	}

	// The store query deliberately returns every managed output linked to
	// the mint transaction. Only the asset anchor index is the historical
	// repair target; another managed output in the same transaction is an
	// expected sibling, not unhealthy retained state.
	if outpoint.Index != candidate.AssetOutputIndex {
		return result, zeroDesc, false
	}
	if outpoint.Hash != finalTx.TxHash() {

		return invalid("retained asset outpoint doesn't match the mint " +
			"transaction txid")
	}

	if len(candidate.MerkleRoot) != 32 {
		return invalid("retained taproot merkle root must be 32 bytes")
	}

	batchKey, err := btcec.ParsePubKey(candidate.BatchKey)
	if err != nil {
		return invalid(fmt.Sprintf("invalid retained batch key: %v", err))
	}
	managedKey, err := btcec.ParsePubKey(candidate.ManagedInternalKey)
	if err != nil {
		return invalid(fmt.Sprintf("invalid managed UTXO internal key: %v", err))
	}

	pOut := packet.Outputs[candidate.AssetOutputIndex]
	var rawInternalKey *btcec.PublicKey
	if len(pOut.TaprootInternalKey) != 0 {
		rawInternalKey, err = schnorr.ParsePubKey(pOut.TaprootInternalKey)
		if err != nil {
			return invalid(fmt.Sprintf("invalid retained raw anchor key: %v",
				err))
		}
		result.AnchorInternalKey = rawInternalKey.SerializeCompressed()
	}

	if len(pOut.Bip32Derivation) == 0 {
		if rawInternalKey == nil {
			return invalid("retained anchor output has no internal key")
		}

		result.Status = CustomAnchorKeyLocatorRequired
		result.Detail = "retained packet proves only the raw anchor key; " +
			"automatic repair is unavailable and wallet-validated operator " +
			"recovery is required"
		return result, zeroDesc, true
	}
	if len(pOut.Bip32Derivation) != 1 {
		return invalid("retained anchor output has conflicting wallet key " +
			"locators")
	}

	desc, err := tappsbt.KeyDescFromBip32Derivation(
		pOut.Bip32Derivation[0],
	)
	if err != nil {
		return invalid(fmt.Sprintf("invalid retained anchor key locator: %v",
			err))
	}
	result.AnchorInternalKey = desc.PubKey.SerializeCompressed()

	expectedBip32, expectedTaproot := tappsbt.Bip32DerivationFromKeyDesc(
		desc, chainParams.HDCoinType,
	)
	if !bytes.Equal(expectedBip32.PubKey,
		pOut.Bip32Derivation[0].PubKey) ||
		!equalUint32s(expectedBip32.Bip32Path,
			pOut.Bip32Derivation[0].Bip32Path) {

		return invalid("retained anchor key locator has the wrong network " +
			"or derivation path")
	}
	if rawInternalKey != nil && !bytes.Equal(
		schnorr.SerializePubKey(rawInternalKey),
		schnorr.SerializePubKey(desc.PubKey),
	) {

		return invalid("retained anchor key locator conflicts with the raw " +
			"anchor key")
	}
	if len(pOut.TaprootBip32Derivation) > 1 {
		return invalid("retained anchor output has conflicting taproot key " +
			"locators")
	}
	if len(pOut.TaprootBip32Derivation) == 1 {
		actual := pOut.TaprootBip32Derivation[0]
		if !bytes.Equal(expectedTaproot.XOnlyPubKey, actual.XOnlyPubKey) ||
			!equalUint32s(expectedTaproot.Bip32Path, actual.Bip32Path) ||
			len(actual.LeafHashes) != 0 {

			return invalid("retained taproot key locator conflicts with the " +
				"wallet descriptor")
		}
	}

	actualOutput := finalTx.TxOut[candidate.AssetOutputIndex]
	expectedOutputKey := txscript.ComputeTaprootOutputKey(
		desc.PubKey, candidate.MerkleRoot,
	)
	expectedScript, err := txscript.PayToTaprootScript(expectedOutputKey)
	if err != nil {
		return invalid(fmt.Sprintf("unable to derive retained anchor script: %v",
			err))
	}
	if !bytes.Equal(expectedScript, actualOutput.PkScript) {
		return invalid("wallet descriptor doesn't bind the committed anchor " +
			"output script")
	}

	managedIsBatchKey := managedKey.IsEqual(batchKey)
	managedIsAnchorKey := managedKey.IsEqual(desc.PubKey)
	if !managedIsBatchKey && !managedIsAnchorKey {
		result.Status = CustomAnchorKeyConflict
		result.Detail = "managed UTXO references neither the historical batch " +
			"key nor the retained custom anchor key"
		return result, desc, true
	}

	if managedIsBatchKey {
		batchOutputKey := txscript.ComputeTaprootOutputKey(
			batchKey, candidate.MerkleRoot,
		)
		batchScript, err := txscript.PayToTaprootScript(batchOutputKey)
		if err != nil {
			return invalid(fmt.Sprintf("unable to derive batch-key anchor "+
				"script: %v", err))
		}
		if bytes.Equal(batchScript, actualOutput.PkScript) {
			result.Status = CustomAnchorKeyHealthy
			result.Detail = "historical batch key already binds the " +
				"committed anchor output"
			return result, desc, true
		}
	}

	if !keyRing.IsLocalKey(ctx, desc) {
		result.Status = CustomAnchorKeyNotLocal
		result.Detail = "retained key locator doesn't derive to the anchor key " +
			"in the backing wallet"
		return result, desc, true
	}
	if managedIsAnchorKey {
		result.Status = CustomAnchorKeyHealthy
		result.Detail = "managed UTXO already references the retained custom " +
			"anchor key with a wallet-verified locator"
		return result, desc, true
	}

	// CustomAnchorKeyRepaired is zero and is used internally to signal that
	// every proof passed and the caller may execute the store CAS.
	result.Status = CustomAnchorKeyRepaired
	return result, desc, true
}

func hasExactHistoricalCustomAnchorMarker(packet *psbt.Packet) bool {
	markerCount := 0
	for _, unknown := range packet.Unknowns {
		if !bytes.Equal(unknown.Key, customAnchorPsbtMarker) {
			continue
		}

		markerCount++
		if !bytes.Equal(unknown.Value, []byte{1}) {
			return false
		}
	}

	return markerCount == 1
}

func decodeCustomAnchorRepairOutpoint(raw []byte) (wire.OutPoint, error) {
	var outpoint wire.OutPoint
	if len(raw) != chainhashSize+4 {
		return outpoint, fmt.Errorf("expected 36 bytes, got %d", len(raw))
	}

	copy(outpoint.Hash[:], raw[:chainhashSize])
	outpoint.Index = binary.LittleEndian.Uint32(raw[chainhashSize:])
	return outpoint, nil
}

func equalUint32s(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}

	return true
}

const chainhashSize = 32
