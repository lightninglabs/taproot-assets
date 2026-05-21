// Package mintpublish provides the implementation of
// tapgarden.MintProofPublisher: it converts minted assets and their proofs
// into universe leaves and ships them through a universe.BatchRegistrar.
package mintpublish

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
)

// Publisher ships minted assets and their proofs to a universe via a
// BatchRegistrar.
type Publisher struct {
	reg       universe.BatchRegistrar
	batchSize int
}

// NewPublisher constructs a Publisher that ships items to reg. batchSize
// controls the number of items per UpsertProofLeafBatch call.
func NewPublisher(reg universe.BatchRegistrar, batchSize int) *Publisher {
	return &Publisher{
		reg:       reg,
		batchSize: batchSize,
	}
}

// PublishMintBatch ships the proofs for a confirmed minting batch.
func (p *Publisher) PublishMintBatch(ctx context.Context,
	params tapgarden.MintBatchPublishParams) error {

	items := make([]*universe.Item, 0, len(params.Assets))
	for _, a := range params.Assets {
		scriptKey := asset.ToSerialized(a.ScriptKey.PubKey)

		mintingProof, ok := params.Proofs[scriptKey]
		if !ok {
			return fmt.Errorf("no minting proof for asset %x",
				scriptKey[:])
		}

		item, err := buildItem(
			a, mintingProof, params.MintTxHash,
			params.AnchorOutIdx,
		)
		if err != nil {
			return fmt.Errorf("unable to build universe item: %w",
				err)
		}

		items = append(items, item)
	}

	numTotal := len(items)
	var sent int
	for start := 0; start < numTotal; start += p.batchSize {
		end := start + p.batchSize
		if end > numTotal {
			end = numTotal
		}

		chunk := items[start:end]
		sent += len(chunk)

		log.Infof("Inserting %d new leaves (%d of %d) into local "+
			"universe", len(chunk), sent, numTotal)

		if err := p.reg.UpsertProofLeafBatch(ctx, chunk); err != nil {
			return fmt.Errorf("unable to register proof leaf "+
				"batch: %w", err)
		}

		log.Infof("Inserted %d new leaves (%d of %d) into local "+
			"universe", len(chunk), sent, numTotal)
	}

	return nil
}

// PublishMintProofUpdates ships post-reorg proof updates to the universe.
func (p *Publisher) PublishMintProofUpdates(ctx context.Context,
	proofs []*proof.Proof) error {

	for idx := range proofs {
		pr := proofs[idx]

		uniID := universe.Identifier{
			AssetID: pr.Asset.ID(),
		}
		if pr.Asset.GroupKey != nil {
			uniID.GroupKey = &pr.Asset.GroupKey.GroupPubKey
		}

		log.Debugf("Updating issuance proof for asset with "+
			"universe, key=%v", spew.Sdump(uniID))

		leafKey := universe.BaseLeafKey{
			OutPoint: wire.OutPoint{
				Hash:  pr.AnchorTx.TxHash(),
				Index: pr.InclusionProof.OutputIndex,
			},
			ScriptKey: &pr.Asset.ScriptKey,
		}

		proofBytes, err := pr.Bytes()
		if err != nil {
			return fmt.Errorf("unable to encode proof: %w", err)
		}

		uniGen := universe.GenesisWithGroup{
			Genesis: pr.Asset.Genesis,
		}
		if pr.Asset.GroupKey != nil {
			uniGen.GroupKey = pr.Asset.GroupKey
		}

		mintingLeaf := &universe.Leaf{
			GenesisWithGroup: uniGen,
			RawProof:         proofBytes,
			Amt:              pr.Asset.Amount,
			Asset:            &pr.Asset,
		}

		_, err = p.reg.UpsertProofLeaf(
			ctx, uniID, leafKey, mintingLeaf,
		)
		if err != nil {
			return fmt.Errorf("unable to update issuance: %w", err)
		}
	}

	return nil
}

// buildItem assembles the universe item for a single newly-minted asset.
func buildItem(a *asset.Asset, mintingProof *proof.Proof,
	mintTxHash chainhash.Hash, anchorOutIdx uint32) (*universe.Item,
	error) {

	assetID := a.ID()

	uniID := universe.Identifier{
		AssetID: assetID,
	}
	if a.GroupKey != nil {
		uniID.GroupKey = &a.GroupKey.GroupPubKey
	}

	log.Debugf("Preparing asset for registration with universe, key=%v",
		spew.Sdump(uniID))

	leafKey := universe.BaseLeafKey{
		OutPoint: wire.OutPoint{
			Hash:  mintTxHash,
			Index: anchorOutIdx,
		},
		ScriptKey: &a.ScriptKey,
	}

	mintingProofBytes, err := mintingProof.Bytes()
	if err != nil {
		return nil, fmt.Errorf("unable to encode proof: %w", err)
	}

	uniGen := universe.GenesisWithGroup{
		Genesis: a.Genesis,
	}
	if a.GroupKey != nil {
		uniGen.GroupKey = a.GroupKey
	}

	mintingLeaf := &universe.Leaf{
		GenesisWithGroup: uniGen,
		RawProof:         mintingProofBytes,
		Amt:              a.Amount,
		Asset:            a,
	}

	return &universe.Item{
		ID:           uniID,
		Key:          leafKey,
		Leaf:         mintingLeaf,
		LogProofSync: true,
	}, nil
}

// Compile-time assertion that *Publisher satisfies the consumer interface
// declared by tapgarden.
var _ tapgarden.MintProofPublisher = (*Publisher)(nil)
