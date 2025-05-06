package tapsend

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/input"
)

var (
	// ErrMissingInputs is an error that is returned if no inputs were
	// provided.
	ErrMissingInputs = fmt.Errorf("no inputs provided")

	// ErrMissingAllocations is an error that is returned if no allocations
	// were provided.
	ErrMissingAllocations = fmt.Errorf("no allocations provided")

	// ErrInputTypesNotEqual is an error that is returned if the input types
	// are not all the same.
	ErrInputTypesNotEqual = fmt.Errorf("input types not all equal")

	// ErrInputGroupMismatch is an error that is returned if the input
	// assets don't all belong to the same asset group.
	ErrInputGroupMismatch = fmt.Errorf("input assets not all of same group")

	// ErrInputOutputSumMismatch is an error that is returned if the sum of
	// the input asset proofs does not match the sum of the output
	// allocations.
	ErrInputOutputSumMismatch = fmt.Errorf("input and output sum mismatch")

	// ErrCommitmentNotSet is an error that is returned if the output
	// commitment is not set for an allocation.
	ErrCommitmentNotSet = fmt.Errorf("output commitment not set")

	// ErrInvalidSibling is an error that is returned if both non-asset
	// leaves and sibling preimage are set for an allocation.
	ErrInvalidSibling = errors.New(
		"both non-asset leaves and sibling preimage set",
	)

	// ErrScriptKeyGenMissing is an error that is returned if the script key
	// generator function is not set.
	ErrScriptKeyGenMissing = errors.New(
		"script key generator function not set for asset allocation",
	)

	// ErrNoSplitRoot is returned if a non-interactive send doesn't specify
	// which output should house the split root asset.
	ErrNoSplitRoot = errors.New(
		"non-interactive transfers must specify which output should " +
			"house the split root asset",
	)
)

// AllocationType is an enum that defines the different types of asset
// allocations that can be created.
type AllocationType uint8

const (
	// AllocationTypeNoAssets is the default allocation type that is used
	// when the allocation type is not important or the allocation does not
	// carry any assets.
	AllocationTypeNoAssets AllocationType = 0

	// CommitAllocationToLocal is an allocation type that is used for
	// allocating assets to the local party.
	CommitAllocationToLocal AllocationType = 1

	// CommitAllocationToRemote is an allocation type that is used for
	// allocating assets to the remote party.
	CommitAllocationToRemote AllocationType = 2

	// CommitAllocationHtlcIncoming is an allocation type that is used for
	// allocating assets to an incoming HTLC output.
	CommitAllocationHtlcIncoming AllocationType = 3

	// CommitAllocationHtlcOutgoing is an allocation type that is used for
	// allocating assets to an outgoing HTLC output.
	CommitAllocationHtlcOutgoing AllocationType = 4

	// SecondLevelHtlcAllocation is an allocation type that is used for
	// allocating assets to a second level HTLC output (HTLC-success for
	// HTLCs accepted by the local node, HTLC-timeout for HTLCs offered by
	// the local node).
	SecondLevelHtlcAllocation AllocationType = 5
)

// ScriptKeyGen is a function type that is used for generating a script key for
// an asset specific script key.
type ScriptKeyGen func(assetID asset.ID) (asset.ScriptKey, error)

// StaticScriptKeyGen is a helper function that returns a script key generator
// function that always returns the same script key.
func StaticScriptKeyGen(scriptKey asset.ScriptKey) ScriptKeyGen {
	return func(asset.ID) (asset.ScriptKey, error) {
		return scriptKey, nil
	}
}

// StaticScriptPubKeyGen is a helper function that returns a script key
// generator function that always returns the same script key, provided as a
// public key.
func StaticScriptPubKeyGen(scriptPubKey *btcec.PublicKey) ScriptKeyGen {
	return func(asset.ID) (asset.ScriptKey, error) {
		return asset.NewScriptKey(scriptPubKey), nil
	}
}

// Allocation is a struct that tracks how many units of assets should be
// allocated to a specific output of an on-chain transaction. An allocation can
// be seen as a recipe/instruction to distribute a certain number of asset units
// to a specific output of an on-chain transaction. The output is mainly
// identified by its output index but also carries along additional information
// that is required for making sure the resulting on-chain outputs can be sorted
// in a deterministic way (that is almost but not exactly following the BIP-69
// rules for sorting transaction outputs).
type Allocation struct {
	// Type is the type of the asset allocation.
	Type AllocationType

	// OutputIndex is the output index of the on-chain transaction which
	// the asset allocation is meant for.
	OutputIndex uint32

	// SplitRoot indicates whether the virtual output(s) created for the
	// allocation should house the split root asset.
	SplitRoot bool

	// InternalKey is the internal key used for the on-chain transaction
	// output.
	InternalKey *btcec.PublicKey

	// NonAssetLeaves is the full list of TapLeaf nodes that aren't any
	// asset commitments. This is used to construct the tapscript sibling
	// for the asset commitment. This is mutually exclusive to the
	// SiblingPreimage field below, only one of them (or none) should be
	// set. If this is a non-asset allocation and both NonAssetLeaves is
	// empty and no SiblingPreimage is set, then we assume a BIP-0086
	// output.
	NonAssetLeaves []txscript.TapLeaf

	// SiblingPreimage is the tapscript sibling preimage that is used to
	// create the tapscript sibling for the asset commitment. This is
	// mutually exclusive to the NonAssetLeaves above, only one of them (or
	// none) should be set. If this is a non-asset allocation and both
	// NonAssetLeaves is empty and no SiblingPreimage is set, then we assume
	// a BIP-0086 output.
	SiblingPreimage *commitment.TapscriptPreimage

	// GenScriptKey is a function that returns the Taproot tweaked key
	// encoding the different spend conditions possible for the asset
	// allocation for a certain asset ID.
	GenScriptKey ScriptKeyGen

	// Amount is the amount of units that should be allocated in total.
	// Available units from different UTXOs are distributed up to this total
	// amount in a deterministic way.
	Amount uint64

	// AssetVersion is the version that the asset allocation should use.
	AssetVersion asset.Version

	// BtcAmount is the amount of BTC that should be sent to the output
	// address of the anchor transaction.
	BtcAmount btcutil.Amount

	// SortTaprootKeyBytes is the Schnorr serialized Taproot output key of
	// the on-chain P2TR output that would be created if there was no asset
	// commitment present. This field should be used for sorting purposes.
	SortTaprootKeyBytes []byte

	// SortCLTV is the SortCLTV timeout for the asset allocation. This is
	// only relevant for sorting purposes and is expected to be zero for any
	// non-HTLC allocation.
	SortCLTV uint32

	// Sequence is the CSV value for the asset allocation. This is only
	// relevant for HTLC second level transactions. This value will be set
	// as the relative time lock on the virtual output.
	Sequence uint32

	// LockTime is the actual CLTV value that will be set on the output.
	LockTime uint64

	// HtlcIndex is the index of the HTLC that the allocation is for. This
	// is only relevant for HTLC allocations.
	HtlcIndex input.HtlcIndex

	// OutputCommitment is the taproot output commitment that is set after
	// fully distributing the coins and creating the asset and TAP trees.
	OutputCommitment *commitment.TapCommitment

	// ProofDeliveryAddress is the address the proof courier should use to
	// upload the proof for this allocation.
	ProofDeliveryAddress *url.URL

	// AltLeaves represent data used to construct an Asset commitment, that
	// will be inserted in the output anchor Tap commitment. These
	// data-carrying leaves are used for a purpose distinct from
	// representing individual Taproot Assets.
	AltLeaves []asset.AltLeaf[asset.Asset]
}

// Validate checks that the allocation is correctly set up and that the fields
// are consistent with each other.
func (a *Allocation) Validate() error {
	// Make sure the two mutually exclusive fields aren't set at the same
	// time.
	if len(a.NonAssetLeaves) > 0 && a.SiblingPreimage != nil {
		return ErrInvalidSibling
	}

	// The script key generator function is required for any allocation that
	// carries assets.
	if a.Type != AllocationTypeNoAssets && a.GenScriptKey == nil {
		return ErrScriptKeyGenMissing
	}

	return nil
}

// tapscriptSibling returns the tapscript sibling preimage from the non-asset
// leaves of the allocation. If there are no non-asset leaves, nil is returned.
func (a *Allocation) tapscriptSibling() (*commitment.TapscriptPreimage, error) {
	if len(a.NonAssetLeaves) == 0 && a.SiblingPreimage == nil {
		return nil, nil
	}

	// The sibling preimage has precedence. Only one of the two fields
	// should be set in any case.
	if a.SiblingPreimage != nil {
		return a.SiblingPreimage, nil
	}

	treeNodes, err := asset.TapTreeNodesFromLeaves(a.NonAssetLeaves)
	if err != nil {
		return nil, fmt.Errorf("error creating tapscript tree nodes: "+
			"%w", err)
	}

	sibling, err := commitment.NewPreimageFromTapscriptTreeNodes(*treeNodes)
	if err != nil {
		return nil, fmt.Errorf("error creating tapscript sibling: %w",
			err)
	}

	return sibling, err
}

// FinalPkScript returns the pkScript calculated from the internal key,
// tapscript sibling and merkle root of the output commitment. If the output
// commitment is not set, ErrCommitmentNotSet is returned.
func (a *Allocation) FinalPkScript() ([]byte, error) {
	// If this is a normal commitment anchor output without any assets, then
	// we'll map the sort Taproot output key to a script directly.
	if a.Type == AllocationTypeNoAssets {
		taprootKey, err := schnorr.ParsePubKey(a.SortTaprootKeyBytes)
		if err != nil {
			return nil, err
		}

		return txscript.PayToTaprootScript(taprootKey)
	}

	if a.OutputCommitment == nil {
		return nil, ErrCommitmentNotSet
	}

	tapscriptSibling, err := a.tapscriptSibling()
	if err != nil {
		return nil, err
	}

	var siblingHash *chainhash.Hash
	if tapscriptSibling != nil {
		siblingHash, err = tapscriptSibling.TapHash()
		if err != nil {
			return nil, err
		}
	}

	tapscriptRoot := a.OutputCommitment.TapscriptRoot(siblingHash)
	taprootOutputKey := txscript.ComputeTaprootOutputKey(
		a.InternalKey, tapscriptRoot[:],
	)

	return txscript.PayToTaprootScript(taprootOutputKey)
}

// AuxLeaf returns the auxiliary leaf for the allocation. If the output
// commitment is not set, ErrCommitmentNotSet is returned.
func (a *Allocation) AuxLeaf() (txscript.TapLeaf, error) {
	if a.OutputCommitment == nil {
		return txscript.TapLeaf{}, ErrCommitmentNotSet
	}

	return a.OutputCommitment.TapLeaf(), nil
}

// MatchesOutput returns true if the unique identifying characteristics of an
// on-chain commitment output match this allocation. The pkScript is calculated
// from the internal key, tapscript sibling and merkle root of the output
// commitment. If the output commitment is not set an error is returned.
func (a *Allocation) MatchesOutput(pkScript []byte, value int64, cltv uint32,
	htlcIndex input.HtlcIndex) (bool, error) {

	finalPkScript, err := a.FinalPkScript()
	if err != nil {
		return false, err
	}

	outputsEqual := bytes.Equal(pkScript, finalPkScript) &&
		value == int64(a.BtcAmount) && cltv == a.SortCLTV &&
		htlcIndex == a.HtlcIndex

	return outputsEqual, nil
}

// FilterByType returns a filter function that can be used to filter a list of
// allocations by the given allocation type.
func FilterByType(allocType AllocationType) func(a *Allocation) bool {
	return func(a *Allocation) bool {
		return a.Type == allocType
	}
}

// FilterByTypeExclude returns a filter function that can be used to filter a
// list of allocations by excluding the given allocation type.
func FilterByTypeExclude(
	excludeAllocType AllocationType) func(a *Allocation) bool {

	return func(a *Allocation) bool {
		return a.Type != excludeAllocType
	}
}

// piece is a struct that tracks the currently available and allocated assets
// for a specific asset ID. It also contains the virtual packet that is being
// built for each asset ID.
type piece struct {
	// assetID is the ID of the asset that is being distributed.
	assetID asset.ID

	// totalAvailable is the sum of all asset outputs that are available for
	// distribution per asset ID.
	totalAvailable uint64

	// allocated is the amount of assets that have been allocated so far.
	allocated uint64

	// proofs is the list of proofs for the assets that make up a piece.
	proofs []*proof.Proof

	// packet is the virtual packet that is being built for the asset ID.
	packet *tappsbt.VPacket
}

// available returns the amount of assets that are still available for
// distribution.
func (p *piece) available() uint64 {
	return p.totalAvailable - p.allocated
}

// sortPieces sorts the given pieces by asset ID and the contained proofs by
// amount and then script key.
func sortPiecesWithProofs(pieces []*piece) {
	// Sort pieces by asset ID.
	sort.Slice(pieces, func(i, j int) bool {
		return bytes.Compare(
			pieces[i].assetID[:], pieces[j].assetID[:],
		) < 0
	})

	// Now sort all the proofs within each piece by amount and then script
	// key. This will give us a stable order for all asset UTXOs.
	for idx := range pieces {
		slices.SortFunc(
			pieces[idx].proofs, func(i, j *proof.Proof) int {
				return AssetSortForInputs(i.Asset, j.Asset)
			},
		)
	}
}

// AssetSortForInputs is a comparison function that should be used to sort asset
// inputs by amount (in reverse order) and then by script key. Using this
// function everywhere we sort inputs will ensure that the inputs are always in
// a predictable and stable order.
func AssetSortForInputs(i, j asset.Asset) int {
	return cmp.Or(
		// Sort amounts in reverse order so that the largest amounts are
		// first.
		cmp.Compare(j.Amount, i.Amount),
		bytes.Compare(
			i.ScriptKey.PubKey.SerializeCompressed(),
			j.ScriptKey.PubKey.SerializeCompressed(),
		),
	)
}

// DistributeCoins allocates a set of inputs (extracted from the given input
// proofs) to virtual outputs as specified by the allocations given. It returns
// a list of virtual packets (one for each distinct asset ID) with virtual
// outputs that sum up to the amounts specified in the allocations. The main
// purpose of this function is to deterministically re-distribute heterogeneous
// asset outputs (asset UTXOs of different sizes from different tranches/asset
// IDs) according to the distribution rules provided as "allocations".
func DistributeCoins(inputs []*proof.Proof, allocations []*Allocation,
	chainParams *address.ChainParams, interactive bool,
	vPktVersion tappsbt.VPacketVersion) ([]*tappsbt.VPacket, error) {

	if len(inputs) == 0 {
		return nil, ErrMissingInputs
	}

	if len(allocations) == 0 {
		return nil, ErrMissingAllocations
	}

	// Count how many asset units are available for distribution.
	var (
		inputSum    uint64
		firstType   = inputs[0].Asset.Type
		firstTapKey = inputs[0].Asset.TapCommitmentKey()
	)
	for _, inputProof := range inputs {
		// We can't have mixed types (normal and collectibles) within
		// the same allocation.
		if firstType != inputProof.Asset.Type {
			return nil, ErrInputTypesNotEqual
		}

		// Allocating assets from different asset groups is not allowed.
		if firstTapKey != inputProof.Asset.TapCommitmentKey() {
			return nil, ErrInputGroupMismatch
		}

		inputSum += inputProof.Asset.Amount
	}

	// Sum up the amounts that are to be allocated to the outputs. We also
	// validate that all the required fields are set and no conflicting
	// fields are set.
	var (
		outputSum     uint64
		haveSplitRoot bool
	)
	for _, allocation := range allocations {
		if err := allocation.Validate(); err != nil {
			return nil, fmt.Errorf("invalid allocation: %w", err)
		}

		outputSum += allocation.Amount
		haveSplitRoot = haveSplitRoot || allocation.SplitRoot
	}

	// Non-interactive transfers need to specify which output should house
	// the split root asset. Because that will need to be the output that
	// goes back to the sender (or to a zero-amount tombstone output the
	// sender owns the internal key for). But in interactive transfers,
	// it doesn't matter which output houses the split root asset, we'll
	// just assign one later if needed.
	if !interactive && !haveSplitRoot {
		return nil, ErrNoSplitRoot
	}

	// Asset change must be allocated upfront as well. We expect the sum of
	// the input proofs to match the sum of the output allocations.
	if inputSum != outputSum {
		return nil, fmt.Errorf("%w: input=%v, output=%v",
			ErrInputOutputSumMismatch, inputSum, outputSum)
	}

	// We group the assets by asset ID, since we'll want to create a single
	// virtual packet per asset ID (with each virtual packet potentially
	// having multiple inputs and outputs).
	groupedProofs := GroupProofsByAssetID(inputs)

	// Each "piece" keeps track of how many assets of a specific asset ID
	// we have already distributed. The pieces are also the main way to
	// reference an asset ID's virtual packet.
	pieces := make([]*piece, 0, len(groupedProofs))
	for assetID, proofsByID := range groupedProofs {
		sumByID := fn.Reduce(
			proofsByID, func(sum uint64, i *proof.Proof) uint64 {
				return sum + i.Asset.Amount
			},
		)

		// Before creating the virtual packet, sort the proofs by
		// amount (in reverse order) then by script key. This ensures
		// deterministic ordering before assigning them to the virtual
		// packet inputs.
		slices.SortFunc(proofsByID, func(i, j *proof.Proof) int {
			return AssetSortForInputs(i.Asset, j.Asset)
		})

		pkt, err := tappsbt.FromProofs(
			proofsByID, chainParams, vPktVersion,
		)
		if err != nil {
			return nil, err
		}

		pieces = append(pieces, &piece{
			assetID:        assetID,
			totalAvailable: sumByID,
			proofs:         proofsByID,
			packet:         pkt,
		})
	}

	// Make sure the pieces are in a stable and reproducible order before we
	// start the distribution.
	sortPiecesWithProofs(pieces)

	for idx := range allocations {
		a := allocations[idx]

		// If the allocation has no assets (commitment anchor output or
		// otherwise), then we can safely skip it.
		if a.Type == AllocationTypeNoAssets {
			continue
		}

		// Find the next piece that has assets left to allocate.
		toFill := a.Amount
		for pieceIdx := range pieces {
			fillDelta, updatedPiece, err := allocatePiece(
				*pieces[pieceIdx], *a, toFill, interactive,
			)
			if err != nil {
				return nil, err
			}

			pieces[pieceIdx] = updatedPiece
			toFill -= fillDelta

			// If the piece has enough assets to fill the
			// allocation, we can exit the loop, unless we also need
			// to create a tombstone output for a non-interactive
			// send. If it only fills part of the allocation, we'll
			// continue to the next piece.
			if toFill == 0 && interactive {
				break
			}
		}
	}

	packets := fn.Map(pieces, func(p *piece) *tappsbt.VPacket {
		return p.packet
	})
	err := ValidateVPacketVersions(packets)
	if err != nil {
		return nil, err
	}

	// If we're doing a non-interactive transfer, we're done here.
	if !interactive {
		return packets, nil
	}

	// For interactive packets we will now assign a split root output (if
	// needed).
	for _, vPkt := range packets {
		// If we have more than 1 output (meaning we are going to split
		// the assets), and we don't have a split root output yet, we
		// select the first output to be the split root. In interactive
		// transfers it doesn't really matter which output is selected.
		if len(vPkt.Outputs) > 1 && !vPkt.HasSplitRootOutput() {
			vPkt.Outputs[0].Type = tappsbt.TypeSplitRoot
		}
	}

	return packets, nil
}

// allocatePiece allocates assets from the given piece to the given allocation,
// if there are units left to allocate. This adds a virtual output to the piece
// and updates the amount of allocated assets. The function returns the amount
// of assets that were allocated and the updated piece.
func allocatePiece(p piece, a Allocation, toFill uint64,
	interactive bool) (uint64, *piece, error) {

	sibling, err := a.tapscriptSibling()
	if err != nil {
		return 0, nil, err
	}

	scriptKey, err := a.GenScriptKey(p.assetID)
	if err != nil {
		return 0, nil, fmt.Errorf("error generating script key for "+
			"allocation: %w", err)
	}

	deliveryAddr := a.ProofDeliveryAddress
	vOut := &tappsbt.VOutput{
		AssetVersion:                 a.AssetVersion,
		Interactive:                  interactive,
		AnchorOutputIndex:            a.OutputIndex,
		AnchorOutputInternalKey:      a.InternalKey,
		AnchorOutputTapscriptSibling: sibling,
		ScriptKey:                    scriptKey,
		ProofDeliveryAddress:         deliveryAddr,
		LockTime:                     a.LockTime,
		RelativeLockTime:             uint64(a.Sequence),
		AltLeaves:                    a.AltLeaves,
	}

	// If we've allocated all pieces, or we don't need to allocate anything
	// to this piece, we might only need to create a tombstone output.
	if p.available() == 0 || toFill == 0 {
		// We don't need a tombstone output for interactive transfers,
		// or recipient outputs (outputs that don't go back to the
		// sender).
		if interactive || !a.SplitRoot {
			return 0, &p, nil
		}

		// Create a zero-amount tombstone output for the split root, if
		// there is no change.
		vOut.Type = tappsbt.TypeSplitRoot
		p.packet.Outputs = append(p.packet.Outputs, vOut)

		return 0, &p, nil
	}

	// We know we have something to allocate, so let's now create a new
	// vOutput for the allocation.
	allocating := toFill
	if p.available() < toFill {
		allocating = p.available()
	}

	// We only need a split root output if this piece is being split. If we
	// consume it fully in this allocation, we can use a simple output.
	consumeFully := p.allocated == 0 && toFill >= p.available()

	// If we're creating a non-interactive packet (e.g. for a TAP address
	// based send), we definitely need a split root, even if there is no
	// change. If there is change, then we also need a split root, even if
	// we're creating a fully interactive packet.
	needSplitRoot := a.SplitRoot && (!interactive || !consumeFully)

	// The only exception is when the split root output is the only output,
	// because it's not being used at all and goes back to the sender.
	splitRootIsOnlyOutput := a.SplitRoot && consumeFully

	outType := tappsbt.TypeSimple
	if needSplitRoot && !splitRootIsOnlyOutput {
		outType = tappsbt.TypeSplitRoot
	}

	// We just need to update the type and amount for this virtual output,
	// everything else can be taken from the allocation itself.
	vOut.Type = outType
	vOut.Amount = allocating
	p.packet.Outputs = append(p.packet.Outputs, vOut)

	p.allocated += allocating

	return allocating, &p, nil
}

// AssignOutputCommitments assigns the output commitments keyed by the output
// index to the corresponding allocations.
func AssignOutputCommitments(allocations []*Allocation,
	outCommitments tappsbt.OutputCommitments) error {

	for idx := range allocations {
		alloc := allocations[idx]

		// Allocations without any assets won't be mapped to an output
		// commitment.
		if alloc.Type == AllocationTypeNoAssets {
			continue
		}

		outCommitment, ok := outCommitments[alloc.OutputIndex]
		if !ok {
			return fmt.Errorf("no output commitment found for "+
				"output index %d", alloc.OutputIndex)
		}

		alloc.OutputCommitment = outCommitment
	}

	return nil
}

// NonAssetExclusionProofs returns an exclusion proof generator that creates
// exclusion proofs for non-asset P2TR outputs in the given allocations.
func NonAssetExclusionProofs(
	allocations []*Allocation) ExclusionProofGenerator {

	return func(target *proof.BaseProofParams,
		isAnchor IsAnchor) error {

		for _, alloc := range allocations {
			// We only need exclusion proofs for allocations that
			// don't have any assets.
			if alloc.Type != AllocationTypeNoAssets {
				continue
			}

			// Create a tapscript exclusion proof for the non-asset
			// leaves of this allocation.
			tsProof, err := proof.CreateTapscriptProof(
				alloc.NonAssetLeaves,
			)
			if err != nil {
				return fmt.Errorf("error creating tapscript "+
					"proof: %w", err)
			}

			target.ExclusionProofs = append(
				target.ExclusionProofs, proof.TaprootProof{
					OutputIndex:    alloc.OutputIndex,
					InternalKey:    alloc.InternalKey,
					TapscriptProof: tsProof,
				},
			)
		}

		return nil
	}
}

// AllocationsFromTemplate creates a list of allocations from a spend template.
// If there is no split output present in the template, one is created to carry
// potential change or a zero-value tombstone output in case of a
// non-interactive transfer. The script key for those change/tombstone outputs
// are set to the NUMS script key and need to be replaced with an actual script
// key (if the change is non-zero) after the coin distribution has been
// performed.
func AllocationsFromTemplate(tpl *tappsbt.VPacket,
	inputSum uint64) ([]*Allocation, bool, error) {

	if len(tpl.Outputs) == 0 {
		return nil, false, fmt.Errorf("spend template has no outputs")
	}

	// We first detect if the outputs are interactive or not. They need to
	// all say the same thing, otherwise we can't proceed.
	isInteractive := tpl.Outputs[0].Interactive
	for idx := 1; idx < len(tpl.Outputs); idx++ {
		if tpl.Outputs[idx].Interactive != isInteractive {
			return nil, false, fmt.Errorf("outputs have " +
				"different interactive flags")
		}
	}

	// Calculate the total amount that is being spent.
	var outputAmount uint64
	for _, out := range tpl.Outputs {
		outputAmount += out.Amount
	}

	// Validate the change amount so we can use it later.
	if outputAmount > inputSum {
		return nil, false, fmt.Errorf("output amount exceeds input sum")
	}
	changeAmount := inputSum - outputAmount

	// In case there is no change/tombstone output, we assume the anchor
	// output indexes are still increasing. So we'll just use the next one
	// after the last output's anchor output index.
	splitOutIndex := tpl.Outputs[len(tpl.Outputs)-1].AnchorOutputIndex + 1

	// If there is no change/tombstone output in the template, we always
	// create one. This will not be used (e.g. turned into an actual virtual
	// output) by the allocation logic if is not needed (when it's an
	// interactive full-value send).
	localAllocation := &Allocation{
		Type:         CommitAllocationToLocal,
		OutputIndex:  splitOutIndex,
		SplitRoot:    true,
		GenScriptKey: StaticScriptKeyGen(asset.NUMSScriptKey),
	}

	// If we have a split root defined in the template, we'll use that as
	// the template for the local allocation.
	if tpl.HasSplitRootOutput() {
		splitRootOut, err := tpl.SplitRootOutput()
		if err != nil {
			return nil, false, err
		}

		setAllocationFieldsFromOutput(localAllocation, splitRootOut)
	}

	// We do need to overwrite the amount of the local allocation with the
	// change amount now. We do _NOT_, however, derive change script keys
	// yet, since we don't know if some of the packets created by the coin
	// distribution might remain an un-spendable zero-amount tombstone
	// output, and we don't want to derive change script keys for those.
	localAllocation.Amount = changeAmount

	// We now create the remote allocations for each non-split output.
	remoteAllocations := make([]*Allocation, 0, len(tpl.Outputs))
	normalOuts := fn.Filter(tpl.Outputs, tappsbt.VOutIsNotSplitRoot)
	for _, out := range normalOuts {
		remoteAllocation := &Allocation{
			Type:      CommitAllocationToRemote,
			SplitRoot: false,
		}

		setAllocationFieldsFromOutput(remoteAllocation, out)
		remoteAllocations = append(remoteAllocations, remoteAllocation)
	}

	allAllocations := append(
		[]*Allocation{localAllocation}, remoteAllocations...,
	)

	return allAllocations, isInteractive, nil
}

// setAllocationFieldsFromOutput sets the fields of the given allocation from
// the given virtual output.
func setAllocationFieldsFromOutput(alloc *Allocation, vOut *tappsbt.VOutput) {
	alloc.Amount = vOut.Amount
	alloc.AssetVersion = vOut.AssetVersion
	alloc.OutputIndex = vOut.AnchorOutputIndex
	alloc.InternalKey = vOut.AnchorOutputInternalKey
	alloc.GenScriptKey = StaticScriptKeyGen(vOut.ScriptKey)
	alloc.Sequence = uint32(vOut.RelativeLockTime)
	alloc.LockTime = vOut.LockTime
	alloc.ProofDeliveryAddress = vOut.ProofDeliveryAddress
	alloc.AltLeaves = vOut.AltLeaves
	alloc.SiblingPreimage = vOut.AnchorOutputTapscriptSibling
}

// GroupProofsByAssetID groups the given proofs by their asset ID.
func GroupProofsByAssetID(proofs []*proof.Proof) map[asset.ID][]*proof.Proof {
	assetIDs := fn.Map(proofs, func(p *proof.Proof) asset.ID {
		return p.Asset.ID()
	})
	uniqueAssetIDs := fn.NewSet(assetIDs...).ToSlice()

	groupedProofs := make(map[asset.ID][]*proof.Proof, len(uniqueAssetIDs))
	for _, assetID := range uniqueAssetIDs {
		groupedProofs[assetID] = fn.Filter(
			proofs, func(p *proof.Proof) bool {
				return p.Asset.ID() == assetID
			},
		)
	}

	return groupedProofs
}
