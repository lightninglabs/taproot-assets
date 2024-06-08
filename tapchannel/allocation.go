package tapchannel

import (
	"bytes"
	"fmt"
	"net/url"
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
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/input"
)

var (
	// ErrMissingInputs is an error that is returned if no inputs were
	// provided.
	ErrMissingInputs = fmt.Errorf("no inputs provided")

	// ErrMissingAllocations is an error that is returned if no allocations
	// were provided.
	ErrMissingAllocations = fmt.Errorf("no allocations provided")

	// ErrInputOutputSumMismatch is an error that is returned if the sum of
	// the input asset proofs does not match the sum of the output
	// allocations.
	ErrInputOutputSumMismatch = fmt.Errorf("input and output sum mismatch")

	// ErrNormalAssetsOnly is an error that is returned if an allocation
	// contains an asset that is not a normal asset (e.g. a collectible).
	ErrNormalAssetsOnly = fmt.Errorf("only normal assets are supported")

	// ErrCommitmentNotSet is an error that is returned if the output
	// commitment is not set for an allocation.
	ErrCommitmentNotSet = fmt.Errorf("output commitment not set")
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
	// for the asset commitment. If this is a non-asset allocation and the
	// list of leaves is empty, then we assume a BIP-0086 output.
	NonAssetLeaves []txscript.TapLeaf

	// ScriptKey is the Taproot tweaked key encoding the different spend
	// conditions possible for the asset allocation.
	ScriptKey asset.ScriptKey

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

	// CLTV is the CLTV timeout for the asset allocation. This is only
	// relevant for sorting purposes and is expected to be zero for any
	// non-HTLC allocation.
	CLTV uint32

	// Sequence is the CSV value for the asset allocation. This is only
	// relevant for HTLC second level transactions.
	Sequence uint32

	// HtlcIndex is the index of the HTLC that the allocation is for. This
	// is only relevant for HTLC allocations.
	HtlcIndex input.HtlcIndex

	// OutputCommitment is the taproot output commitment that is set after
	// fully distributing the coins and creating the asset and TAP trees.
	OutputCommitment *commitment.TapCommitment

	// ProofDeliveryAddress is the address the proof courier should use to
	// upload the proof for this allocation.
	ProofDeliveryAddress *url.URL
}

// tapscriptSibling returns the tapscript sibling preimage from the non-asset
// leaves of the allocation. If there are no non-asset leaves, nil is returned.
func (a *Allocation) tapscriptSibling() (*commitment.TapscriptPreimage, error) {
	if len(a.NonAssetLeaves) == 0 {
		return nil, nil
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

// finalPkScript returns the pkScript calculated from the internal key,
// tapscript sibling and merkle root of the output commitment. If the output
// commitment is not set, ErrCommitmentNotSet is returned.
func (a *Allocation) finalPkScript() ([]byte, error) {
	// If this is a normal commitment anchor output without any assets, then
	// we'll map the sort Taproot output key to a script directly.
	if a.Type == AllocationTypeNoAssets {
		taprootKey, err := schnorr.ParsePubKey(a.SortTaprootKeyBytes)
		if err != nil {
			return nil, err
		}

		return tapscript.PayToTaprootScript(taprootKey)
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

	return tapscript.PayToTaprootScript(taprootOutputKey)
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

	finalPkScript, err := a.finalPkScript()
	if err != nil {
		return false, err
	}

	outputsEqual := bytes.Equal(pkScript, finalPkScript) &&
		value == int64(a.BtcAmount) && cltv == a.CLTV &&
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
		sort.Slice(pieces[idx].proofs, func(i, j int) bool {
			assetI := pieces[idx].proofs[i].Asset
			assetJ := pieces[idx].proofs[j].Asset

			// If amounts are equal, sort by script key.
			if assetI.Amount == assetJ.Amount {
				keyI := assetI.ScriptKey.PubKey
				keyJ := assetJ.ScriptKey.PubKey
				return bytes.Compare(
					keyI.SerializeCompressed(),
					keyJ.SerializeCompressed(),
				) < 0
			}

			// Otherwise, sort by amount, but in reverse order so
			// that the largest amounts are first.
			return assetI.Amount > assetJ.Amount
		})
	}
}

// DistributeCoins allocates a set of inputs (extracted from the given input
// proofs) to virtual outputs as specified by the allocations given. It returns
// a list of virtual packets (one for each distinct asset ID) with virtual
// outputs that sum up to the amounts specified in the allocations. The main
// purpose of this function is to deterministically re-distribute heterogeneous
// asset outputs (asset UTXOs of different sizes from different tranches/asset
// IDs) according to the distribution rules provided as "allocations".
func DistributeCoins(inputs []*proof.Proof, allocations []*Allocation,
	chainParams *address.ChainParams) ([]*tappsbt.VPacket, error) {

	if len(inputs) == 0 {
		return nil, ErrMissingInputs
	}

	if len(allocations) == 0 {
		return nil, ErrMissingAllocations
	}

	// Count how many asset units are available for distribution.
	var inputSum uint64
	for _, inputProof := range inputs {
		if inputProof.Asset.Type != asset.Normal {
			return nil, ErrNormalAssetsOnly
		}

		inputSum += inputProof.Asset.Amount
	}

	// Sum up the amounts that are to be allocated to the outputs.
	var outputSum uint64
	for _, allocation := range allocations {
		outputSum += allocation.Amount
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
	assetIDs := fn.Map(inputs, func(input *proof.Proof) asset.ID {
		return input.Asset.ID()
	})
	uniqueAssetIDs := fn.NewSet(assetIDs...).ToSlice()

	// Each "piece" keeps track of how many assets of a specific asset ID
	// we have already distributed. The pieces are also the main way to
	// reference an asset ID's virtual packet.
	pieces := make([]*piece, len(uniqueAssetIDs))
	for i, assetID := range uniqueAssetIDs {
		proofsByID := fn.Filter(inputs, func(i *proof.Proof) bool {
			return i.Asset.ID() == assetID
		})
		sumByID := fn.Reduce(
			proofsByID, func(sum uint64, i *proof.Proof) uint64 {
				return sum + i.Asset.Amount
			},
		)

		pkt, err := tappsbt.FromProofs(proofsByID, chainParams)
		if err != nil {
			return nil, err
		}

		pieces[i] = &piece{
			assetID:        assetID,
			totalAvailable: sumByID,
			proofs:         proofsByID,
			packet:         pkt,
		}
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
			p := pieces[pieceIdx]

			// Skip fully allocated pieces
			if p.available() == 0 {
				continue
			}

			// We know we have something to allocate, so let's now
			// create a new vOutput for the allocation.
			allocating := toFill
			if p.available() < toFill {
				allocating = p.available()
			}

			// We only need a split root output if this piece is
			// being split. If we consume it fully in this
			// allocation, we can use a simple output.
			consumeFully := p.allocated == 0 &&
				toFill >= p.available()

			outType := tappsbt.TypeSimple
			if a.SplitRoot && !consumeFully {
				outType = tappsbt.TypeSplitRoot
			}

			sibling, err := a.tapscriptSibling()
			if err != nil {
				return nil, err
			}

			deliveryAddr := a.ProofDeliveryAddress
			vOut := &tappsbt.VOutput{
				Amount:                       allocating,
				AssetVersion:                 a.AssetVersion,
				Type:                         outType,
				Interactive:                  true,
				AnchorOutputIndex:            a.OutputIndex,
				AnchorOutputInternalKey:      a.InternalKey,
				AnchorOutputTapscriptSibling: sibling,
				ScriptKey:                    a.ScriptKey,
				ProofDeliveryAddress:         deliveryAddr,
			}
			p.packet.Outputs = append(p.packet.Outputs, vOut)

			// TODO(guggero): If sequence > 0, set the sequence
			// on the inputs of the packet.

			p.allocated += allocating
			toFill -= allocating

			// If the piece has enough assets to fill the
			// allocation, we can exit the loop. If it only fills
			// part of the allocation, we'll continue to the next
			// piece.
			if toFill == 0 {
				break
			}
		}
	}

	packets := fn.Map(pieces, func(p *piece) *tappsbt.VPacket {
		return p.packet
	})
	return packets, nil
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
	allocations []*Allocation) tapsend.ExclusionProofGenerator {

	return func(target *proof.BaseProofParams,
		isAnchor tapsend.IsAnchor) error {

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
