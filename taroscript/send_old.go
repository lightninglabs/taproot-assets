package taroscript

import (
	"errors"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"golang.org/x/exp/maps"
)

var (
	// ErrMissingInputAsset is an error returned when we attempt to spend
	// to a Taro address from an input that does not contain
	// the matching asset.
	ErrMissingInputAsset = errors.New(
		"send: Input does not contain requested asset",
	)

	// ErrInsufficientInputAsset is an error returned when we attempt
	// to spend to a Taro address from an input that contains
	// insufficient asset funds.
	ErrInsufficientInputAsset = errors.New(
		"send: Input asset value is insufficient",
	)

	// ErrInvalidOutputIndexes is an error returned when we attempt to spend
	// to Bitcoin output indexes that do not start at 0 or
	// are not continuous.
	ErrInvalidOutputIndexes = errors.New(
		"send: Output indexes not starting at 0 and continuous",
	)

	// ErrMissingSplitAsset is an error returned when we attempt to look up
	// a split asset in a map and the specified asset is not found.
	ErrMissingSplitAsset = errors.New(
		"send: split asset not found",
	)

	// ErrMissingAssetCommitment is an error returned when we attempt to
	// look up an Asset commitment in a map and the specified commitment
	// is not found.
	ErrMissingAssetCommitment = errors.New(
		"send: Asset commitment not found",
	)

	// ErrMissingTaroCommitment is an error returned when we attempt to
	// look up a Taro commitment in a map and the specified commitment
	// is not found.
	ErrMissingTaroCommitment = errors.New(
		"send: Taro commitment not found",
	)
)

const (
	// DummyAmtSats is the default amount of sats we'll use in Bitcoin
	// outputs embedding Taro commitments. This value just needs to be
	// greater than dust, and we assume that this value is updated to match
	// the input asset bearing UTXOs before finalizing the transfer TX.
	DummyAmtSats = btcutil.Amount(1_000)

	// SendConfTarget is the confirmation target we'll use to query for
	// a fee estimate.
	SendConfTarget = 6
)

// SpendDelta stores the information needed to prepare new asset leaves or a
// split commitment, and validated a spend with the Taro VM. SpendDelta is also
// used to create the final TaroCommitments for each receiver.
type SpendDelta struct {
	// NewAsset is the Asset that will be validated by the Taro VM.
	// In the case of an asset split, it is the root locator that also
	// contains the split commitment. Otherwise, it is the asset that will
	// be sent to the receiver.
	NewAsset asset.Asset

	// InputAssets maps asset PrevIDs to Assets being spent by the sender.
	InputAssets commitment.InputSet

	// Locators maps AssetCommitmentKeys for all receivers to splitLocators.
	// The locators are used to create split commitments, and store indexes
	// for each receiver's corresponding Bitcoin output.
	Locators SpendLocators

	// SplitCommitment contains all data needed to validate and commit to an
	// asset split.

	// NOTE: This is nil unless the InputAsset is being split.
	SplitCommitment *commitment.SplitCommitment
}

// SpendCommitments stores the Taro commitment for each receiver
// (including the sender), which is needed to create
// the final PSBT for the transfer.
type SpendCommitments = map[[32]byte]commitment.TaroCommitment

// SpendLocators stores a split locators for each receiver, keyed by their
// AssetCommitmentKey. These locators are used to create split commitments and
// the final PSBT for the transfer. AssetCommitmentKeys are unique to each asset
// and each receiver due to the inclusion of the receiver's ScriptKey.
type SpendLocators = map[[32]byte]commitment.SplitLocator

// Copy returns a deep copy of a SpendDelta.
func (s *SpendDelta) Copy() SpendDelta {
	// Copy the fields that are not maps directly; the other fields must
	// maintain their nil-ness, and therefore require an extra check.
	newDelta := SpendDelta{
		NewAsset:        *s.NewAsset.Copy(),
		SplitCommitment: s.SplitCommitment,
	}

	if s.InputAssets != nil {
		inputAssets := make(commitment.InputSet)
		maps.Copy(inputAssets, s.InputAssets)
		newDelta.InputAssets = inputAssets
	}

	if s.Locators != nil {
		locators := make(SpendLocators)
		maps.Copy(locators, s.Locators)
		newDelta.Locators = locators
	}

	return newDelta
}

// createDummyOutput creates a new Bitcoin transaction output that is later
// used to embed a Taro commitment.
func createDummyOutput() *wire.TxOut {
	// The dummy PkScript is the same size as an encoded P2TR output.
	newOutput := wire.TxOut{
		Value:    int64(DummyAmtSats),
		PkScript: make([]byte, 34),
	}
	return &newOutput
}

// CreateDummyLocators creates a set of split locators with continuous output
// indexes, starting for 0. These mock locators are used for initial split
// commitment validation, and are the default for the final PSBT.
func CreateDummyLocators(stateKeys [][32]byte) SpendLocators {
	locators := make(SpendLocators)
	for i := uint32(0); i < uint32(len(stateKeys)); i++ {
		index := i
		locators[stateKeys[i]] = commitment.SplitLocator{
			OutputIndex: index,
		}
	}
	return locators
}

// Build a template TX with dummy outputs
// TODO(jhb): godoc
func CreateTemplatePsbt(locators SpendLocators) (*psbt.Packet, error) {
	// Check if our locators are valid, and if we will need to add extra
	// outputs to fill in the gaps between locators.
	taroOnlySpend, err := AreValidIndexes(locators)
	if err != nil {
		return nil, err
	}

	// Calculate the number of outputs we need for our template TX.
	maxOutputIndex := uint32(len(locators))

	// If there is a gap in our locators, we need to find the
	// largest output index to properly size our template TX.
	if !taroOnlySpend {
		maxOutputIndex = 0
		for _, locator := range locators {
			if locator.OutputIndex > maxOutputIndex {
				maxOutputIndex = locator.OutputIndex
			}
		}
		// Output indexes are 0-indexed, so we need to increment this
		// to account for the 0th output.
		maxOutputIndex++
	}

	txTemplate := wire.NewMsgTx(2)
	for i := uint32(0); i < maxOutputIndex; i++ {
		txTemplate.AddTxOut(createDummyOutput())
	}

	spendPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to make psbt packet: %w", err)
	}

	return spendPkt, nil
}

// AreValidIndexes checks a set of split locators to check for the minimum
// number of locators, and tests if the locators could be used for a Taro-only
// spend, i.e. a TX that does not need other outputs added to be valid.
func AreValidIndexes(locators SpendLocators) (bool, error) {
	// Sanity check the output indexes provided by the sender. There must be
	// at least two indexes; one for the receiver, and one for the change
	// commitment for the sender.
	if locators == nil {
		return false, ErrInvalidOutputIndexes
	}

	idxCount := len(locators)
	if idxCount < 2 {
		return false, ErrInvalidOutputIndexes
	}

	// If the indexes start from 0 and form a continuous range, then the
	// resulting TX would be valid without any changes (Taro-only spend).
	taroOnlySpend := true
	txoLocators := maps.Values(locators)
	sort.Slice(txoLocators, func(i, j int) bool {
		return txoLocators[i].OutputIndex < txoLocators[j].OutputIndex
	})
	for i := uint32(0); i < uint32(idxCount); i++ {
		if txoLocators[i].OutputIndex != i {
			taroOnlySpend = false
			break
		}
	}

	return taroOnlySpend, nil
}

// IsValidInput verifies that the Taro commitment of the input contains an
// asset that could be spent to the given Taro address.
func IsValidInput(input *commitment.TaroCommitment,
	addr address.Taro, inputScriptKey btcec.PublicKey,
	net address.ChainParams) (*asset.Asset, bool, error) {

	fullValue := false

	// The input and address networks must match.
	if !address.IsForNet(addr.ChainParams.TaroHRP, &net) {
		return nil, fullValue, address.ErrMismatchedHRP
	}

	// The top-level Taro tree must have a non-empty asset tree at the leaf
	// specified in the address.
	inputCommitments := input.Commitments()
	assetCommitment, ok := inputCommitments[addr.TaroCommitmentKey()]
	if !ok {
		return nil, fullValue, fmt.Errorf("input commitment does "+
			"not contain asset_id=%x: %w", addr.TaroCommitmentKey(),
			ErrMissingInputAsset)
	}

	// The asset tree must have a non-empty Asset at the location
	// specified by the sender's script key.
	assetCommitmentKey := asset.AssetCommitmentKey(
		addr.ID(), &inputScriptKey, addr.GroupKey == nil,
	)
	inputAsset, _, err := assetCommitment.AssetProof(assetCommitmentKey)
	if err != nil {
		return nil, fullValue, err
	}

	if inputAsset == nil {
		return nil, fullValue, fmt.Errorf("input commitment does not "+
			"contain leaf with script_key=%x: %w",
			inputScriptKey.SerializeCompressed(),
			ErrMissingInputAsset)
	}

	// For Normal assets, we also check that the input asset amount is
	// at least as large as the amount specified in the address.
	// If the input amount is exactly the amount specified in the address,
	// the spend must use an unspendable zero-value root split.
	if inputAsset.Type == asset.Normal {
		if inputAsset.Amount < addr.Amount {
			return nil, fullValue, ErrInsufficientInputAsset
		}

		if inputAsset.Amount == addr.Amount {
			fullValue = true
		}
	} else {
		// Collectible assets always require the spending split to use an
		// unspendable zero-value root split.
		fullValue = true
	}

	return inputAsset, fullValue, nil
}

// PrepareAssetSplitSpend computes a split commitment with the given input and
// spend information. Input MUST be checked as valid beforehand, and locators
// MUST be checked for validity beforehand if provided.
//
// TODO(jhb): This assumes only 2 split outputs / 1 receiver; needs update
// to support multiple receivers.
func PrepareAssetSplitSpend(addr address.Taro, prevInput asset.PrevID,
	scriptKey btcec.PublicKey, delta SpendDelta) (*SpendDelta, error) {

	updatedDelta := delta.Copy()

	// Generate the keys used to look up split locators for each receiver.
	senderStateKey := asset.AssetCommitmentKey(
		addr.ID(), &scriptKey, addr.GroupKey == nil,
	)
	receiverStateKey := addr.AssetCommitmentKey()

	// If no locators are provided, we create a split with mock locators to
	// verify that the desired split is possible. We can later regenerate a
	// split with the final output indexes.
	if updatedDelta.Locators == nil {
		updatedDelta.Locators = CreateDummyLocators(
			[][32]byte{senderStateKey, receiverStateKey},
		)
	}

	senderLocator := updatedDelta.Locators[senderStateKey]
	receiverLocator := updatedDelta.Locators[receiverStateKey]

	inputAsset := updatedDelta.InputAssets[prevInput]

	// Populate the remaining fields in the splitLocators before generating
	// the splitCommitment.
	senderLocator.AssetID = addr.ID()
	senderLocator.ScriptKey = asset.ToSerialized(&scriptKey)
	senderLocator.Amount = inputAsset.Amount - addr.Amount
	updatedDelta.Locators[senderStateKey] = senderLocator

	receiverLocator.AssetID = addr.ID()
	receiverLocator.ScriptKey = asset.ToSerialized(&addr.ScriptKey)
	receiverLocator.Amount = addr.Amount
	updatedDelta.Locators[receiverStateKey] = receiverLocator

	// Enforce an unspendable root split if the split sends the full value
	// of the input asset or if the split sends a collectible.
	if (senderLocator.Amount == 0 || inputAsset.Type == asset.Collectible) &&
		senderLocator.ScriptKey != asset.NUMSCompressedKey {

		return nil, commitment.ErrInvalidScriptKey
	}

	splitCommitment, err := commitment.NewSplitCommitment(
		inputAsset, prevInput.OutPoint,
		&senderLocator, &receiverLocator,
	)
	if err != nil {
		return nil, err
	}

	updatedDelta.NewAsset = *splitCommitment.RootAsset
	updatedDelta.InputAssets = splitCommitment.PrevAssets
	updatedDelta.SplitCommitment = splitCommitment

	return &updatedDelta, nil
}

// PrepareAssetCompleteSpend computes a new asset leaf for spends that
// fully consume the input, i.e. collectibles or an equal-valued send. Input
// MUST be checked as valid beforehand.
func PrepareAssetCompleteSpend(addr address.Taro, prevInput asset.PrevID,
	delta SpendDelta) *SpendDelta {

	updatedDelta := delta.Copy()

	// We'll now create a new copy of the old asset, swapping out the
	// script key. We blank out the tweaked key information as this is now
	// an external asset.
	//
	// TODO(roasbeef): make locators here, and make sure they exist like
	// above
	newAsset := updatedDelta.InputAssets[prevInput].Copy()
	newAsset.ScriptKey.PubKey = &addr.ScriptKey
	newAsset.ScriptKey.TweakedScriptKey = nil

	// Record the PrevID of the input asset in a Witness for the new asset.
	// This Witness still needs a valid signature for the new asset
	// to be valid.
	//
	// TODO(roasbeef): when we fix #121, then this should also be a
	// ZeroPrevID
	newAsset.PrevWitnesses = []asset.Witness{
		{
			PrevID:          &prevInput,
			TxWitness:       nil,
			SplitCommitment: nil,
		},
	}

	updatedDelta.NewAsset = *newAsset

	return &updatedDelta
}

// CompleteAssetSpend updates the new Asset by creating a signature over the
// asset transfer, verifying the transfer with the Taro VM, and attaching that
// signature to the new Asset.
func CompleteAssetSpend(internalKey btcec.PublicKey, delta SpendDelta,
	signer Signer, validator TxValidator) (*SpendDelta, error) {

	updatedDelta := delta.Copy()

	// Create a Taro virtual transaction representing the asset transfer.
	virtualTx, _, err := VirtualTx(
		&updatedDelta.NewAsset, updatedDelta.InputAssets,
	)
	if err != nil {
		return nil, err
	}

	// For each input asset leaf, we need to produce a witness.
	// Update the input of the virtual TX, generate a witness,
	// and attach it to the copy of the new Asset.
	validatedAsset := updatedDelta.NewAsset.Copy()
	prevWitnessCount := len(updatedDelta.NewAsset.PrevWitnesses)

	for idx := 0; idx < prevWitnessCount; idx++ {
		prevAssetID := updatedDelta.NewAsset.PrevWitnesses[idx].PrevID
		prevAsset := updatedDelta.InputAssets[*prevAssetID]
		virtualTxCopy := VirtualTxWithInput(
			virtualTx, prevAsset, uint32(idx), nil,
		)

		newWitness, err := SignTaprootKeySpend(
			internalKey, virtualTxCopy, prevAsset, 0,
			txscript.SigHashDefault, signer,
		)
		if err != nil {
			return nil, err
		}

		validatedAsset.PrevWitnesses[idx].TxWitness = *newWitness
	}

	// Create an instance of the Taro VM and validate the transfer.
	verifySpend := func(splitAssets []*commitment.SplitAsset) error {
		err := validator.Execute(
			validatedAsset, splitAssets, updatedDelta.InputAssets,
		)
		if err != nil {
			return err
		}
		return nil
	}

	// If the transfer contains no asset splits, we only need to validate
	// the new asset with its witness attached.
	if updatedDelta.SplitCommitment == nil {
		if err := verifySpend(nil); err != nil {
			return nil, err
		}

		updatedDelta.NewAsset = *validatedAsset

		return &updatedDelta, nil
	}

	// If the transfer includes an asset split, we have to validate each
	// split asset to ensure that our new Asset is committing to
	// a valid SplitCommitment.
	splitAssets := maps.Values(updatedDelta.SplitCommitment.SplitAssets)
	err = verifySpend(splitAssets)
	if err != nil {
		return nil, err
	}

	// Update each split asset to store the root asset with the witness
	// attached, so the receiver can verify inclusion of the root asset.
	for key := range updatedDelta.SplitCommitment.SplitAssets {
		updatedDelta.SplitCommitment.SplitAssets[key].Asset.
			PrevWitnesses[0].SplitCommitment.
			RootAsset = *validatedAsset.Copy()
	}

	updatedDelta.NewAsset = *validatedAsset

	return &updatedDelta, nil
}

// CreateSpendCommitments creates the final set of TaroCommitments representing
// the asset send. The input TaroCommitment must become a valid change
// commitment by removing the input asset and adding the root split asset
// if present. The receiver TaroCommitment must include the output asset.
func CreateSpendCommitments(inputCommitment *commitment.TaroCommitment,
	prevInput asset.PrevID, spend SpendDelta, addr address.Taro,
	senderScriptKey btcec.PublicKey) (SpendCommitments, error) {

	// Store TaroCommitments keyed by the public key of the receiver.
	commitments := make(SpendCommitments, len(spend.Locators))

	inputAsset := spend.InputAssets[prevInput]

	// Remove the spent Asset from the AssetCommitment of the sender.  Fail
	// if the input AssetCommitment or Asset were not in the input
	// TaroCommitment.
	inputCommitmentCopy, err := inputCommitment.Copy()
	if err != nil {
		return nil, err
	}
	inputCommitments := inputCommitmentCopy.Commitments()
	senderCommitment, ok := inputCommitments[inputAsset.TaroCommitmentKey()]
	if !ok {
		return nil, ErrMissingAssetCommitment
	}

	inputAssets := senderCommitment.Assets()
	_, ok = inputAssets[inputAsset.AssetCommitmentKey()]
	if !ok {
		return nil, ErrMissingInputAsset
	}

	if err := senderCommitment.Update(inputAsset, true); err != nil {
		return nil, err
	}

	receiverStateKey := addr.AssetCommitmentKey()

	var (
		senderStateKey     [32]byte
		receiverCommitment *commitment.AssetCommitment
	)

	// If there was no asset split, the validated asset should be used to
	// build an AssetCommitment for the receiver.
	if spend.SplitCommitment == nil {
		senderStateKey = asset.AssetCommitmentKey(
			addr.ID(), &senderScriptKey, addr.GroupKey == nil,
		)
		var err error
		receiverCommitment, err = commitment.NewAssetCommitment(
			&spend.NewAsset,
		)
		if err != nil {
			return nil, err
		}
	} else {
		// If the input asset was split, the validated asset is the
		// root asset for the split, and should be included in the
		// AssetCommitment of the sender.
		senderStateKey = spend.NewAsset.AssetCommitmentKey()

		err := senderCommitment.Update(&spend.NewAsset, false)
		if err != nil {
			return nil, err
		}

		// Fetch the receiver asset from the split commitment and build
		// an AssetCommitment for the receiver.
		receiverLocator := spend.Locators[receiverStateKey]
		receiverAsset, ok := spend.SplitCommitment.SplitAssets[receiverLocator]
		if !ok {
			return nil, ErrMissingSplitAsset
		}

		// At this point, we have the receiver's taro commitment.
		// However we need to blank out the split commitment proof, as
		// the receiver doesn't know of this information yet. The final
		// commitment will be to a leaf without the split commitment
		// proof.
		receiverAssetCopy := receiverAsset.Copy()
		receiverAssetCopy.PrevWitnesses[0].SplitCommitment = nil

		receiverCommitment, err = commitment.NewAssetCommitment(
			receiverAssetCopy,
		)
		if err != nil {
			return nil, err
		}
	}

	// Update the top-level TaroCommitment of the sender. This'll
	// effectively commit to all the new spend details.
	//
	// TODO(jhb): Add emptiness check for senderCommitment, to prune the
	// AssetCommitment entirely when possible.
	senderTaroCommitment := *inputCommitmentCopy
	err = senderTaroCommitment.Update(senderCommitment, false)
	if err != nil {
		return nil, err
	}

	commitments[senderStateKey] = senderTaroCommitment

	// Create a Taro tree for the receiver.
	receiverTaroCommitment, err := commitment.NewTaroCommitment(
		receiverCommitment,
	)
	if err != nil {
		return nil, err
	}

	commitments[receiverStateKey] = *receiverTaroCommitment

	return commitments, nil
}

// CreateSpendOutputs updates a PSBT with outputs embedding TaroCommitments
// involved in an asset send. The sender must attach the Bitcoin input holding
// the corresponding Taro input asset to this PSBT before finalizing the TX.
// Locators MUST be checked beforehand.
func CreateSpendOutputs(addr address.Taro, locators SpendLocators,
	internalKey, scriptKey btcec.PublicKey,
	commitments SpendCommitments, pkt *psbt.Packet) error {

	// Fetch the TaroCommitment for both sender and receiver.
	senderStateKey := asset.AssetCommitmentKey(
		addr.ID(), &scriptKey, addr.GroupKey == nil,
	)
	receiverStateKey := addr.AssetCommitmentKey()

	senderCommitment, ok := commitments[senderStateKey]
	if !ok {
		return ErrMissingTaroCommitment
	}
	receiverCommitment, ok := commitments[receiverStateKey]
	if !ok {
		return ErrMissingTaroCommitment
	}

	// Create the scripts corresponding to each receiver's TaroCommitment.
	//
	// NOTE: We currently default to the Taro commitment having no sibling
	// in the Tapscript tree. Any sibling would need to be checked to
	// verify that it is not also a Taro commitment.
	receiverScript, err := PayToAddrScript(
		addr.InternalKey, nil, receiverCommitment,
	)
	if err != nil {
		return err
	}
	senderScript, err := PayToAddrScript(
		internalKey, nil, senderCommitment,
	)
	if err != nil {
		return err
	}

	// Embed the TaroCommitments in their respective transaction outputs.
	senderIndex := locators[senderStateKey].OutputIndex
	pkt.UnsignedTx.TxOut[senderIndex].PkScript = senderScript

	receiverIndex := locators[receiverStateKey].OutputIndex
	pkt.UnsignedTx.TxOut[receiverIndex].PkScript = receiverScript

	return nil
}
