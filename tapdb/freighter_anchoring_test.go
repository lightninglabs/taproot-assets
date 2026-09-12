package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// blockContextFor synthesizes a block context (hash, header, merkle
// proof) containing the given transaction, the way the re-org
// watcher's sensing enriches witnesses.
func blockContextFor(t *testing.T, tx *wire.MsgTx,
	nonce uint32) (chainhash.Hash, wire.BlockHeader,
	proof.TxMerkleProof) {

	header := wire.BlockHeader{
		Version: 2,
		Nonce:   nonce,
	}
	merkle, err := proof.NewTxMerkleProof([]*wire.MsgTx{tx}, 0)
	require.NoError(t, err)

	return header.BlockHash(), header, *merkle
}

// TestPorterAnchoringPersistence drives a transfer through the porter
// site's persistence cycle against a real database: the phase-1
// pending write, the rebuilt-and-applied confirmation, a re-organized
// re-confirmation (convergence: no duplicated state, refreshed block
// info), the potency-tier unconfirm, and act-level abandonment with
// full compensation. Every handler body is applied twice at its
// stage: phases coalesce and deliveries redeliver, so twice must
// equal once.
func TestPorterAnchoringPersistence(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	// The registry-style executor: full query set, one transaction.
	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// One confirmed input asset.
	targetScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &targetScriptKey,
		amt:         16,
	}})

	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, 1)
	inputAsset := allAssets[0]
	assetID := inputAsset.ID()

	inputAnchorPoint := wire.OutPoint{
		Hash:  assetGen.anchorTxs[0].TxHash(),
		Index: 0,
	}

	// The input's proof file, stored where the rebuild will fetch
	// it (asset_proofs, keyed by the asset row).
	inputProof := randProof(t, inputAsset.Asset)
	inputFile, err := proof.NewFile(proof.V0, *inputProof)
	require.NoError(t, err)
	var inputFileBuf bytes.Buffer
	require.NoError(t, inputFile.Encode(&inputFileBuf))

	var inputAssetDBID int64
	err = db.DB.QueryRowContext(
		ctx, "SELECT assets.asset_id FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE script_keys.tweaked_script_key = $1",
		inputAsset.ScriptKey.PubKey.SerializeCompressed(),
	).Scan(&inputAssetDBID)
	require.NoError(t, err)
	require.NoError(t, db.UpsertAssetProofByID(ctx, ProofUpdateByID{
		AssetID:   inputAssetDBID,
		ProofFile: inputFileBuf.Bytes(),
	}))

	// The transfer: one input, two outputs (receiver + change).
	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputAnchorPoint})
	newAnchorTx.TxIn[0].SignatureScript = []byte{}
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	newScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})
	newScriptKey2 := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})
	const newAmt = 9

	// Both output suffixes reference the spent input in their
	// witnesses, as real suffixes do: the rebuild matches each
	// output to its inputs through these references.
	inputPrevID := asset.PrevID{
		OutPoint: inputAnchorPoint,
		ID:       assetID,
		ScriptKey: asset.ToSerialized(
			inputAsset.ScriptKey.PubKey,
		),
	}

	receiverAsset := inputAsset.Copy()
	receiverAsset.ScriptKey = newScriptKey
	receiverAsset.PrevWitnesses = []asset.Witness{{
		PrevID:    &inputPrevID,
		TxWitness: [][]byte{{0x01}},
	}}
	receiverProof := randProof(t, receiverAsset)
	receiverProofBytes, err := receiverProof.Bytes()
	require.NoError(t, err)

	senderAsset := inputAsset.Copy()
	senderAsset.ScriptKey = newScriptKey2
	senderAsset.PrevWitnesses = []asset.Witness{{
		PrevID:    &inputPrevID,
		TxWitness: [][]byte{{0x01}},
	}}
	senderProof := randProof(t, senderAsset)
	senderProofBytes, err := senderProof.Bytes()
	require.NoError(t, err)

	newWitness := asset.Witness{
		PrevID:    &asset.PrevID{},
		TxWitness: [][]byte{{0x01}, {0x02}},
	}
	rootHash := [32]byte{0x10}
	makeAnchor := func(index uint32, script byte) tapfreighter.Anchor {
		return tapfreighter.Anchor{
			Value: 1000,
			OutPoint: wire.OutPoint{
				Hash:  anchorTxHash,
				Index: index,
			},
			InternalKey: keychain.KeyDescriptor{
				PubKey: test.RandPubKey(t),
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(
						rand.Int31(),
					),
					Index: uint32(test.RandInt[int32]()),
				},
			},
			TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
			MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
			PkScript: bytes.Repeat(
				[]byte{script}, 34,
			),
		}
	}

	parcel := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		TransferTime:       time.Now(),
		ChainFees:          100,
		Inputs: []tapfreighter.TransferInput{{
			PrevID: inputPrevID,
			Amount: inputAsset.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor:         makeAnchor(0, 0x01),
			ScriptKey:      newScriptKey,
			ScriptKeyLocal: true,
			Amount:         newAmt,
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: receiverProofBytes,
			Position:    0,
		}, {
			Anchor:         makeAnchor(1, 0x02),
			ScriptKey:      newScriptKey2,
			ScriptKeyLocal: true,
			Amount:         inputAsset.Amount - newAmt,
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: senderProofBytes,
			Position:    1,
		}},
	}

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)

	// Phase 1: the pending write, inside a caller-owned transaction
	// (as the anchoring registration runs it).
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyPendingParcel(
				ctx, q, parcel, leaseOwner, leaseExpiry,
			)
		},
	)
	require.NoError(t, err)

	parcels, err := assetsStore.QueryParcels(ctx, nil, true)
	require.NoError(t, err)
	require.Len(t, parcels, 1)

	// Leased assets are included: the pending write leases the
	// input.
	assetCount := func() int {
		assets, err := assetsStore.FetchAllAssets(
			ctx, true, true, nil,
		)
		require.NoError(t, err)

		return len(assets)
	}
	require.Equal(t, 1, assetCount())

	// rebuildAndApply mirrors the porter site's OnWitnessed: rebuild
	// the confirmation from stored state plus a block context, then
	// apply it, in one transaction.
	rebuildAndApply := func(blockHash chainhash.Hash,
		header wire.BlockHeader, merkle proof.TxMerkleProof,
		height, txIndex uint32) error {

		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				conf, burns, err := assetsStore.
					RebuildAnchorConfirm(
						ctx, q, newAnchorTx,
						blockHash, height, txIndex,
						header, merkle, "test note",
					)
				if err != nil {
					return err
				}

				_, err = assetsStore.ApplyAnchorTxConfirm(
					ctx, q, conf, burns,
				)

				return err
			},
		)
	}

	// The anchor confirms in block A.
	blockHashA, headerA, merkleA := blockContextFor(t, newAnchorTx, 1)
	require.NoError(
		t, rebuildAndApply(blockHashA, headerA, merkleA, 600, 0),
	)

	// The input is spent, two new assets materialized, and the
	// parcel is no longer pending (proof delivery flags aside).
	assets, err := assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 3)

	spentCount := 0
	for _, dbAsset := range assets {
		if dbAsset.IsSpent {
			spentCount++
		}
	}
	require.Equal(t, 1, spentCount)

	// A redelivered confirmation with the same block context applied
	// twice equals once: no duplicated rows, same chain info.
	require.NoError(
		t, rebuildAndApply(blockHashA, headerA, merkleA, 600, 0),
	)
	require.Equal(t, 3, assetCount())

	chainTxA, err := db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Equal(t, blockHashA[:], chainTxA.BlockHash)

	// Convergence under re-confirmation: the same transaction
	// re-confirms in block B after a re-org. No duplicate rows; the
	// chain info refreshes.
	blockHashB, headerB, merkleB := blockContextFor(t, newAnchorTx, 2)
	require.NoError(
		t, rebuildAndApply(blockHashB, headerB, merkleB, 601, 0),
	)
	require.Equal(t, 3, assetCount())

	transfers, err := db.QueryAssetTransfers(
		ctx, sqlc.QueryAssetTransfersParams{
			AnchorTxHash: anchorTxHash[:],
		},
	)
	require.NoError(t, err)
	require.Len(t, transfers, 1)

	chainTx, err := db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Equal(t, blockHashB[:], chainTx.BlockHash)

	// The potency-tier downgrade: the witness was lost, the
	// confirmation is withdrawn, nothing else moves. Applied twice:
	// a redelivered downgrade equals one.
	unconfirm := func() error {
		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyAnchorTxUnconfirm(
					ctx, q, anchorTxHash,
				)
			},
		)
	}
	require.NoError(t, unconfirm())
	require.NoError(t, unconfirm())

	chainTx, err = db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)
	require.Equal(t, 3, assetCount())

	// It re-confirms once more (block B again).
	require.NoError(
		t, rebuildAndApply(blockHashB, headerB, merkleB, 601, 0),
	)

	// Act-level loss: a conflicting transaction buried. Everything
	// staked on this transfer reverses.
	abandon := func() error {
		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				_, err := assetsStore.ApplyTransferAbandonment(
					ctx, q, anchorTxHash, nil,
				)
				return err
			},
		)
	}
	require.NoError(t, abandon())

	// The materialized outputs are gone, the input is unspent
	// again, and its lease is released (visible without leased
	// inclusion).
	assets, err = assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.False(t, assets[0].IsSpent)

	// The chain transaction is unconfirmed and the transfer is
	// superseded: it must not be resumed.
	chainTx, err = db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)

	parcels, err = assetsStore.QueryParcels(ctx, nil, true)
	require.NoError(t, err)
	require.Len(t, parcels, 0)

	var superseded bool
	err = db.DB.QueryRowContext(
		ctx, "SELECT superseded FROM asset_transfers "+
			"WHERE anchor_txn_id IN (SELECT txn_id "+
			"FROM chain_txns WHERE txid = $1)",
		anchorTxHash[:],
	).Scan(&superseded)
	require.NoError(t, err)
	require.True(t, superseded)

	// A redelivered abandonment converges to the same end state.
	require.NoError(t, abandon())

	assets, err = assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.False(t, assets[0].IsSpent)

	parcels, err = assetsStore.QueryParcels(ctx, nil, true)
	require.NoError(t, err)
	require.Len(t, parcels, 0)
}

// TestPorterAnchoringRebuildAggregated drives the confirmation rebuild
// against a transfer that carries two independent same-asset
// transitions in one anchor transaction — the shape of an aggregated
// sweep. Each output descends from exactly one input, so each rebuilt
// proof file must extend its own input's file: the association is by
// witness reference, and asset ID alone cannot decide it.
func TestPorterAnchoringRebuildAggregated(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	newKey := func() asset.ScriptKey {
		return asset.NewScriptKeyBip86(keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Family: test.RandInt[keychain.KeyFamily](),
				Index:  uint32(test.RandInt[int32]()),
			},
		})
	}

	// Two confirmed inputs of the same asset under one anchor
	// UTXO, held by distinct script keys.
	inKeyA, inKeyB := newKey(), newKey()

	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &inKeyA,
		amt:         16,
	}, {
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &inKeyB,
		amt:         16,
	}})

	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, 2)

	byKey := func(key asset.ScriptKey) *asset.ChainAsset {
		for _, a := range allAssets {
			if a.ScriptKey.PubKey.IsEqual(key.PubKey) {
				return a
			}
		}
		t.Fatalf("input asset not found")

		return nil
	}
	inputA, inputB := byKey(inKeyA), byKey(inKeyB)
	require.Equal(t, inputA.ID(), inputB.ID())
	assetID := inputA.ID()

	inputAnchorPoint := assetGen.anchorPoints[0]

	// Store each input's proof file where the rebuild fetches it.
	storeInputFile := func(in *asset.ChainAsset) {
		inputProof := randProof(t, in.Asset)
		file, err := proof.NewFile(proof.V0, *inputProof)
		require.NoError(t, err)
		var buf bytes.Buffer
		require.NoError(t, file.Encode(&buf))

		var dbID int64
		err = db.DB.QueryRowContext(
			ctx, "SELECT assets.asset_id FROM assets "+
				"JOIN script_keys ON assets.script_key_id = "+
				"script_keys.script_key_id "+
				"WHERE script_keys.tweaked_script_key = $1",
			in.ScriptKey.PubKey.SerializeCompressed(),
		).Scan(&dbID)
		require.NoError(t, err)
		require.NoError(t, db.UpsertAssetProofByID(
			ctx, ProofUpdateByID{
				AssetID:   dbID,
				ProofFile: buf.Bytes(),
			},
		))
	}
	storeInputFile(inputA)
	storeInputFile(inputB)

	prevIDA := asset.PrevID{
		OutPoint:  inputAnchorPoint,
		ID:        assetID,
		ScriptKey: asset.ToSerialized(inKeyA.PubKey),
	}
	prevIDB := asset.PrevID{
		OutPoint:  inputAnchorPoint,
		ID:        assetID,
		ScriptKey: asset.ToSerialized(inKeyB.PubKey),
	}

	// One anchor transaction spending the shared input UTXO, with
	// one output per transition.
	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputAnchorPoint})
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	// Output 0 descends from input B and output 1 from input A: the
	// crosswise order defeats any first-input bias in the rebuild.
	outKey0, outKey1 := newKey(), newKey()

	makeSuffix := func(in *asset.ChainAsset, prevID asset.PrevID,
		outKey asset.ScriptKey, outIndex uint32) []byte {

		outAsset := in.Copy()
		outAsset.ScriptKey = outKey
		outAsset.PrevWitnesses = []asset.Witness{{
			PrevID:    &prevID,
			TxWitness: [][]byte{{0x01}},
		}}
		suffix := randProof(t, outAsset)
		suffix.InclusionProof.OutputIndex = outIndex
		suffixBytes, err := suffix.Bytes()
		require.NoError(t, err)

		return suffixBytes
	}

	makeAnchor := func(index uint32, script byte) tapfreighter.Anchor {
		return tapfreighter.Anchor{
			Value: 1000,
			OutPoint: wire.OutPoint{
				Hash:  anchorTxHash,
				Index: index,
			},
			InternalKey: keychain.KeyDescriptor{
				PubKey: test.RandPubKey(t),
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(
						rand.Int31(),
					),
					Index: uint32(test.RandInt[int32]()),
				},
			},
			TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
			MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
			PkScript:         bytes.Repeat([]byte{script}, 34),
		}
	}

	newWitness := asset.Witness{
		PrevID:    &asset.PrevID{},
		TxWitness: [][]byte{{0x01}, {0x02}},
	}
	rootHash := [32]byte{0x10}

	parcel := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		TransferTime:       time.Now(),
		ChainFees:          100,
		Inputs: []tapfreighter.TransferInput{{
			PrevID: prevIDA,
			Amount: inputA.Amount,
		}, {
			PrevID: prevIDB,
			Amount: inputB.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor:         makeAnchor(0, 0x01),
			ScriptKey:      outKey0,
			ScriptKeyLocal: true,
			Amount:         inputB.Amount,
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: makeSuffix(inputB, prevIDB, outKey0, 0),
			Position:    0,
		}, {
			Anchor:         makeAnchor(1, 0x02),
			ScriptKey:      outKey1,
			ScriptKeyLocal: true,
			Amount:         inputA.Amount,
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: makeSuffix(inputA, prevIDA, outKey1, 1),
			Position:    1,
		}},
	}

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyPendingParcel(
				ctx, q, parcel, leaseOwner,
				time.Now().Add(time.Hour),
			)
		},
	)
	require.NoError(t, err)

	blockHash, header, merkle := blockContextFor(t, newAnchorTx, 7)
	conf, _, err := assetsStore.RebuildConfirmEvent(
		ctx, newAnchorTx, blockHash, 1451, 0, header, merkle, "",
	)
	require.NoError(t, err)
	require.Len(t, conf.FinalProofs, 2)

	// Each output's file must be its own input's file plus the
	// suffix: two proofs, the first one carrying the matching input
	// script key, and no additional input files attached.
	wantInputKey := map[uint32]*asset.ScriptKey{
		0: &inKeyB, 1: &inKeyA,
	}
	for _, annotated := range conf.FinalProofs {
		file := &proof.File{}
		err := file.Decode(bytes.NewReader(annotated.Blob))
		require.NoError(t, err)
		require.Equal(t, 2, file.NumProofs())

		last, err := file.ProofAt(1)
		require.NoError(t, err)
		require.Empty(t, last.AdditionalInputs)

		inputKey := wantInputKey[last.InclusionProof.OutputIndex]
		require.NotNil(t, inputKey)

		inputProof, err := file.ProofAt(0)
		require.NoError(t, err)
		require.True(t, inputProof.Asset.ScriptKey.PubKey.IsEqual(
			inputKey.PubKey,
		))
	}
}

// TestPorterAnchoringApplySharedAnchorOutput drives the confirmation
// application against a transfer whose outputs carry two distinct
// assets at the same anchor outpoint under the same script key — the
// shape of a multi-asset HTLC swept in one transaction. Each output
// must materialize its own asset row with its own proof file; the
// (script key, anchor UTXO) pair alone cannot identify a row.
func TestPorterAnchoringApplySharedAnchorOutput(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	newKey := func() asset.ScriptKey {
		return asset.NewScriptKeyBip86(keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Family: test.RandInt[keychain.KeyFamily](),
				Index:  uint32(test.RandInt[int32]()),
			},
		})
	}

	// Two confirmed inputs of two distinct assets.
	inKeyA, inKeyB := newKey(), newKey()

	assetGen := newAssetGenerator(t, 2, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &inKeyA,
		amt:         16,
	}, {
		assetGen:    assetGen.assetGens[1],
		anchorPoint: assetGen.anchorPoints[1],
		scriptKey:   &inKeyB,
		amt:         16,
	}})

	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, 2)

	byKey := func(key asset.ScriptKey) *asset.ChainAsset {
		for _, a := range allAssets {
			if a.ScriptKey.PubKey.IsEqual(key.PubKey) {
				return a
			}
		}
		t.Fatalf("input asset not found")

		return nil
	}
	inputA, inputB := byKey(inKeyA), byKey(inKeyB)
	require.NotEqual(t, inputA.ID(), inputB.ID())

	// Store each input's proof file where the rebuild fetches it.
	storeInputFile := func(in *asset.ChainAsset) {
		inputProof := randProof(t, in.Asset)
		file, err := proof.NewFile(proof.V0, *inputProof)
		require.NoError(t, err)
		var buf bytes.Buffer
		require.NoError(t, file.Encode(&buf))

		var dbID int64
		err = db.DB.QueryRowContext(
			ctx, "SELECT assets.asset_id FROM assets "+
				"JOIN script_keys ON assets.script_key_id = "+
				"script_keys.script_key_id "+
				"WHERE script_keys.tweaked_script_key = $1",
			in.ScriptKey.PubKey.SerializeCompressed(),
		).Scan(&dbID)
		require.NoError(t, err)
		require.NoError(t, db.UpsertAssetProofByID(
			ctx, ProofUpdateByID{
				AssetID:   dbID,
				ProofFile: buf.Bytes(),
			},
		))
	}
	storeInputFile(inputA)
	storeInputFile(inputB)

	prevIDA := asset.PrevID{
		OutPoint:  assetGen.anchorPoints[0],
		ID:        inputA.ID(),
		ScriptKey: asset.ToSerialized(inKeyA.PubKey),
	}
	prevIDB := asset.PrevID{
		OutPoint:  assetGen.anchorPoints[1],
		ID:        inputB.ID(),
		ScriptKey: asset.ToSerialized(inKeyB.PubKey),
	}

	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: assetGen.anchorPoints[0],
	})
	newAnchorTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: assetGen.anchorPoints[1],
	})
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	// Both transitions land at output 0 under one shared script key.
	sharedKey := newKey()

	makeSuffix := func(in *asset.ChainAsset,
		prevID asset.PrevID) []byte {

		outAsset := in.Copy()
		outAsset.ScriptKey = sharedKey
		outAsset.PrevWitnesses = []asset.Witness{{
			PrevID:    &prevID,
			TxWitness: [][]byte{{0x01}},
		}}
		suffix := randProof(t, outAsset)
		suffix.InclusionProof.OutputIndex = 0
		suffixBytes, err := suffix.Bytes()
		require.NoError(t, err)

		return suffixBytes
	}

	sharedAnchor := tapfreighter.Anchor{
		Value: 1000,
		OutPoint: wire.OutPoint{
			Hash:  anchorTxHash,
			Index: 0,
		},
		InternalKey: keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamily(rand.Int31()),
				Index:  uint32(test.RandInt[int32]()),
			},
		},
		TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
		MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
		PkScript:         bytes.Repeat([]byte{0x01}, 34),
	}

	newWitness := asset.Witness{
		PrevID:    &asset.PrevID{},
		TxWitness: [][]byte{{0x01}, {0x02}},
	}
	rootHash := [32]byte{0x10}

	parcel := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		TransferTime:       time.Now(),
		ChainFees:          100,
		Inputs: []tapfreighter.TransferInput{{
			PrevID: prevIDA,
			Amount: inputA.Amount,
		}, {
			PrevID: prevIDB,
			Amount: inputB.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor:         sharedAnchor,
			ScriptKey:      sharedKey,
			ScriptKeyLocal: true,
			Amount:         inputA.Amount,
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: makeSuffix(inputA, prevIDA),
			Position:    0,
		}, {
			Anchor:         sharedAnchor,
			ScriptKey:      sharedKey,
			ScriptKeyLocal: true,
			Amount:         inputB.Amount,
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: makeSuffix(inputB, prevIDB),
			Position:    1,
		}},
	}

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyPendingParcel(
				ctx, q, parcel, leaseOwner,
				time.Now().Add(time.Hour),
			)
		},
	)
	require.NoError(t, err)

	rebuildAndApply := func(nonce uint32) error {
		blockHash, header, merkle := blockContextFor(
			t, newAnchorTx, nonce,
		)

		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				conf, burns, err := assetsStore.
					RebuildAnchorConfirm(
						ctx, q, newAnchorTx,
						blockHash, 1451, 0,
						header, merkle, "",
					)
				if err != nil {
					return err
				}

				_, err = assetsStore.ApplyAnchorTxConfirm(
					ctx, q, conf, burns,
				)

				return err
			},
		)
	}
	require.NoError(t, rebuildAndApply(1))

	// Both assets materialized at the shared anchor output, each
	// with its own proof file ending in its own leaf.
	assertMaterialized := func() {
		rows, err := db.DB.QueryContext(
			ctx, "SELECT genesis_assets.asset_id, "+
				"asset_proofs.proof_file "+
				"FROM assets "+
				"JOIN genesis_assets ON assets.genesis_id = "+
				"genesis_assets.gen_asset_id "+
				"JOIN asset_proofs ON asset_proofs.asset_id = "+
				"assets.asset_id "+
				"JOIN script_keys ON assets.script_key_id = "+
				"script_keys.script_key_id "+
				"WHERE script_keys.tweaked_script_key = $1",
			sharedKey.PubKey.SerializeCompressed(),
		)
		require.NoError(t, err)
		defer rows.Close()

		found := make(map[asset.ID]bool)
		for rows.Next() {
			var (
				assetIDBytes []byte
				blob         []byte
			)
			require.NoError(t, rows.Scan(&assetIDBytes, &blob))

			var assetID asset.ID
			copy(assetID[:], assetIDBytes)

			file := &proof.File{}
			require.NoError(
				t, file.Decode(bytes.NewReader(blob)),
			)
			last, err := file.LastProof()
			require.NoError(t, err)
			require.Equal(t, assetID, last.Asset.ID())

			found[assetID] = true
		}
		require.NoError(t, rows.Err())
		require.Len(t, found, 2)
		require.True(t, found[inputA.ID()])
		require.True(t, found[inputB.ID()])
	}
	assertMaterialized()

	// Convergence: a re-applied confirmation leaves the same two
	// rows, not duplicates or cross-written proofs.
	require.NoError(t, rebuildAndApply(1))
	assertMaterialized()

	// Abandonment compensates both leaves.
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			_, err := assetsStore.ApplyTransferAbandonment(
				ctx, q, anchorTxHash, nil,
			)
			return err
		},
	)
	require.NoError(t, err)

	var remaining int
	err = db.DB.QueryRowContext(
		ctx, "SELECT count(*) FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE script_keys.tweaked_script_key = $1",
		sharedKey.PubKey.SerializeCompressed(),
	).Scan(&remaining)
	require.NoError(t, err)
	require.Equal(t, 0, remaining)
}

// TestPorterAnchoringZeroValueSweep asserts the rebuilt confirmation
// derives the zero-value sweep set from stored state.
//
// The live confirmation event carries the funding step's selection out
// of porter memory; the watcher path rebuilds the event from rows, and
// a rebuild that omits the set never marks the swept anchors. The mark
// (swept_txn_id) is the only durable guard FetchOrphanUTXOs consults,
// so once the sweep lease expires, coin selection offers the outpoint
// again and the next transfer funds a transaction spending a UTXO the
// chain already consumed — the registration and pending write commit
// before broadcast fails, and the transfer wedges on every resume.
func TestPorterAnchoringZeroValueSweep(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// One confirmed input asset, with its proof file stored where
	// the rebuild fetches it.
	targetScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &targetScriptKey,
		amt:         16,
	}})

	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, 1)
	inputAsset := allAssets[0]

	inputAnchorPoint := wire.OutPoint{
		Hash:  assetGen.anchorTxs[0].TxHash(),
		Index: 0,
	}

	inputProof := randProof(t, inputAsset.Asset)
	inputFile, err := proof.NewFile(proof.V0, *inputProof)
	require.NoError(t, err)
	var inputFileBuf bytes.Buffer
	require.NoError(t, inputFile.Encode(&inputFileBuf))

	var inputAssetDBID int64
	err = db.DB.QueryRowContext(
		ctx, "SELECT assets.asset_id FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE script_keys.tweaked_script_key = $1",
		inputAsset.ScriptKey.PubKey.SerializeCompressed(),
	).Scan(&inputAssetDBID)
	require.NoError(t, err)
	require.NoError(t, db.UpsertAssetProofByID(ctx, ProofUpdateByID{
		AssetID:   inputAssetDBID,
		ProofFile: inputFileBuf.Bytes(),
	}))

	// A zero-value anchor: a managed UTXO holding only a tombstone,
	// unswept and unleased, which the sweeper offers to funding.
	zeroValuePoint := insertOrphanUTXO(
		t, ctx, db, assetsStore, 212, 5, false,
	)

	orphanPoints := func() []wire.OutPoint {
		orphans, err := assetsStore.FetchOrphanUTXOs(ctx)
		require.NoError(t, err)

		points := make([]wire.OutPoint, len(orphans))
		for i, orphan := range orphans {
			points[i] = orphan.OutPoint
		}

		return points
	}
	require.Contains(t, orphanPoints(), zeroValuePoint)

	// The transfer: the asset input plus the zero-value sweep, one
	// full-value output.
	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputAnchorPoint})
	newAnchorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: zeroValuePoint})
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	inputPrevID := asset.PrevID{
		OutPoint: inputAnchorPoint,
		ID:       inputAsset.ID(),
		ScriptKey: asset.ToSerialized(
			inputAsset.ScriptKey.PubKey,
		),
	}

	newScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})

	receiverAsset := inputAsset.Copy()
	receiverAsset.ScriptKey = newScriptKey
	receiverAsset.PrevWitnesses = []asset.Witness{{
		PrevID:    &inputPrevID,
		TxWitness: [][]byte{{0x01}},
	}}
	receiverProof := randProof(t, receiverAsset)
	receiverProofBytes, err := receiverProof.Bytes()
	require.NoError(t, err)

	parcel := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		TransferTime:       time.Now(),
		ChainFees:          100,
		Inputs: []tapfreighter.TransferInput{{
			PrevID: inputPrevID,
			Amount: inputAsset.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor: tapfreighter.Anchor{
				Value: 1000,
				OutPoint: wire.OutPoint{
					Hash:  anchorTxHash,
					Index: 0,
				},
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							rand.Int31(),
						),
						Index: uint32(
							test.RandInt[int32](),
						),
					},
				},
				TaprootAssetRoot: bytes.Repeat(
					[]byte{0x1}, 32,
				),
				MerkleRoot: bytes.Repeat([]byte{0x1}, 32),
				PkScript:   bytes.Repeat([]byte{0x01}, 34),
			},
			ScriptKey:      newScriptKey,
			ScriptKeyLocal: true,
			Amount:         inputAsset.Amount,
			WitnessData: []asset.Witness{{
				PrevID:    &inputPrevID,
				TxWitness: [][]byte{{0x01}, {0x02}},
			}},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				[32]byte{0x10}, 100,
			),
			ProofSuffix: receiverProofBytes,
			Position:    0,
		}},
		ZeroValueInputs: []*tapfreighter.ZeroValueInput{{
			OutPoint: zeroValuePoint,
		}},
	}

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)

	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyPendingParcel(
				ctx, q, parcel, leaseOwner, leaseExpiry,
			)
		},
	)
	require.NoError(t, err)

	rebuildAndApply := func(nonce uint32) {
		blockHash, header, merkle := blockContextFor(
			t, newAnchorTx, nonce,
		)
		err := executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				conf, burns, err := assetsStore.
					RebuildAnchorConfirm(
						ctx, q, newAnchorTx,
						blockHash, 600, 0, header,
						merkle, "",
					)
				if err != nil {
					return err
				}

				_, err = assetsStore.ApplyAnchorTxConfirm(
					ctx, q, conf, burns,
				)

				return err
			},
		)
		require.NoError(t, err)
	}
	rebuildAndApply(1)

	// The pending write only leased the zero-value anchor; the
	// lease is released on expiry (a year, in production). The
	// swept mark must outlive it, or the next funding round
	// re-selects an outpoint this transaction already spent.
	outpointBytes, err := encodeOutpoint(zeroValuePoint)
	require.NoError(t, err)
	require.NoError(t, db.DeleteUTXOLease(ctx, outpointBytes))

	require.NotContains(
		t, orphanPoints(), zeroValuePoint,
		"confirmed sweep re-offered to coin selection: the "+
			"rebuilt confirmation did not mark it swept",
	)

	// A redelivered confirmation converges.
	rebuildAndApply(1)
	require.NotContains(t, orphanPoints(), zeroValuePoint)

	// Abandonment reverses the mark: the sweeping transaction is
	// gone from the surviving chain, so the anchor is genuinely
	// unspent and must be offered again.
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			_, err := assetsStore.ApplyTransferAbandonment(
				ctx, q, anchorTxHash, nil,
			)
			return err
		},
	)
	require.NoError(t, err)
	require.Contains(t, orphanPoints(), zeroValuePoint)
}

// rivalryWorld is a confirmed transfer against a real database, with
// an optional superseded rival spending the same inputs and an
// optional second input shared by both. The database handle's
// concrete type is build-tag dependent, so the world exposes bound
// helpers instead of the handle itself.
type rivalryWorld struct {
	inputPoint  wire.OutPoint
	secondPoint wire.OutPoint
	oldPassive  wire.OutPoint
	inputDBID   int64
	secondDBID  int64
	passiveDBID int64
	transferID  int64
	rivalID     int64

	abandon       func(t *testing.T, foreclosure *wire.MsgTx)
	unconfirm     func(t *testing.T)
	confirmRival  func(t *testing.T)
	assetSpent    func(t *testing.T, dbID int64) bool
	leaseHeld     func(t *testing.T, point wire.OutPoint) bool
	superseded    func(t *testing.T, transferID int64) bool
	abandoned     func(t *testing.T, transferID int64) bool
	passiveProofs func(t *testing.T) int
}

// buildRivalryWorld builds a rivalryWorld: two confirmed assets at
// distinct anchors (the transfer's input and a passive holding it
// re-anchors), a third as a second input when secondInput is set, the
// transfer applied and confirmed against them, and — when plantRival
// is set — a superseded rival spending the same inputs with its own
// anchor still unconfirmed.
func buildRivalryWorld(t *testing.T, plantRival,
	secondInput bool) *rivalryWorld {

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	randScriptKey := func() asset.ScriptKey {
		return asset.NewScriptKeyBip86(keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Family: test.RandInt[keychain.KeyFamily](),
				Index:  uint32(test.RandInt[int32]()),
			},
		})
	}
	targetScriptKey := randScriptKey()
	secondScriptKey := randScriptKey()

	assetGen := newAssetGenerator(t, 3, 2)
	descs := []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &targetScriptKey,
		amt:         16,
	}, {
		assetGen:    assetGen.assetGens[1],
		anchorPoint: assetGen.anchorPoints[1],
		amt:         5,
	}}
	if secondInput {
		descs = append(descs, assetDesc{
			assetGen:    assetGen.assetGens[2],
			anchorPoint: assetGen.anchorPoints[2],
			scriptKey:   &secondScriptKey,
			amt:         7,
		})
	}
	assetGen.genAssets(t, assetsStore, descs)

	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, len(descs))

	var inputAsset, secondAsset, passiveAsset *asset.ChainAsset
	for _, dbAsset := range allAssets {
		switch {
		case dbAsset.ScriptKey.PubKey.IsEqual(targetScriptKey.PubKey):
			inputAsset = dbAsset

		case dbAsset.ScriptKey.PubKey.IsEqual(secondScriptKey.PubKey):
			secondAsset = dbAsset

		default:
			passiveAsset = dbAsset
		}
	}
	require.NotNil(t, inputAsset)
	require.NotNil(t, passiveAsset)
	require.Equal(t, secondInput, secondAsset != nil)

	inputPoint := wire.OutPoint{
		Hash: assetGen.anchorTxs[0].TxHash(),
	}
	oldPassive := wire.OutPoint{
		Hash: assetGen.anchorTxs[1].TxHash(),
	}
	var secondPoint wire.OutPoint
	if secondInput {
		secondPoint = wire.OutPoint{
			Hash: assetGen.anchorTxs[2].TxHash(),
		}
	}

	dbIDFor := func(chainAsset *asset.ChainAsset) int64 {
		var id int64
		err := db.DB.QueryRowContext(
			ctx, "SELECT assets.asset_id FROM assets "+
				"JOIN script_keys ON "+
				"assets.script_key_id = "+
				"script_keys.script_key_id "+
				"WHERE script_keys.tweaked_script_key "+
				"= $1",
			chainAsset.ScriptKey.PubKey.
				SerializeCompressed(),
		).Scan(&id)
		require.NoError(t, err)

		return id
	}
	inputDBID := dbIDFor(inputAsset)
	passiveDBID := dbIDFor(passiveAsset)
	var secondDBID int64
	if secondInput {
		secondDBID = dbIDFor(secondAsset)
	}

	inputProof := randProof(t, inputAsset.Asset)
	inputFile, err := proof.NewFile(proof.V0, *inputProof)
	require.NoError(t, err)
	var inputFileBuf bytes.Buffer
	require.NoError(t, inputFile.Encode(&inputFileBuf))
	require.NoError(t, db.UpsertAssetProofByID(
		ctx, ProofUpdateByID{
			AssetID:   inputDBID,
			ProofFile: inputFileBuf.Bytes(),
		},
	))

	// The transfer: its inputs, one full-value output of the first.
	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputPoint})
	if secondInput {
		newAnchorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: secondPoint})
	}
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	prevIDFor := func(chainAsset *asset.ChainAsset,
		point wire.OutPoint) asset.PrevID {

		return asset.PrevID{
			OutPoint: point,
			ID:       chainAsset.ID(),
			ScriptKey: asset.ToSerialized(
				chainAsset.ScriptKey.PubKey,
			),
		}
	}
	inputPrevID := prevIDFor(inputAsset, inputPoint)

	transferInputs := []tapfreighter.TransferInput{{
		PrevID: inputPrevID,
		Amount: inputAsset.Amount,
	}}
	if secondInput {
		transferInputs = append(
			transferInputs, tapfreighter.TransferInput{
				PrevID: prevIDFor(secondAsset, secondPoint),
				Amount: secondAsset.Amount,
			},
		)
	}

	newScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})

	receiverAsset := inputAsset.Copy()
	receiverAsset.ScriptKey = newScriptKey
	receiverAsset.PrevWitnesses = []asset.Witness{{
		PrevID:    &inputPrevID,
		TxWitness: [][]byte{{0x01}},
	}}
	receiverProof := randProof(t, receiverAsset)
	receiverProofBytes, err := receiverProof.Bytes()
	require.NoError(t, err)

	parcel := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		TransferTime:       time.Now(),
		ChainFees:          100,
		Inputs:             transferInputs,
		Outputs: []tapfreighter.TransferOutput{{
			Anchor: tapfreighter.Anchor{
				Value: 1000,
				OutPoint: wire.OutPoint{
					Hash: anchorTxHash,
				},
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							rand.Int31(),
						),
						Index: uint32(
							test.RandInt[int32](),
						),
					},
				},
				TaprootAssetRoot: bytes.Repeat(
					[]byte{0x1}, 32,
				),
				MerkleRoot: bytes.Repeat(
					[]byte{0x1}, 32,
				),
				PkScript: bytes.Repeat(
					[]byte{0x01}, 34,
				),
			},
			ScriptKey:      newScriptKey,
			ScriptKeyLocal: true,
			Amount:         inputAsset.Amount,
			WitnessData: []asset.Witness{{
				PrevID:    &inputPrevID,
				TxWitness: [][]byte{{0x01}, {0x02}},
			}},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				[32]byte{0x10}, 100,
			),
			ProofSuffix: receiverProofBytes,
			Position:    0,
		}},
	}

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)

	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyPendingParcel(
				ctx, q, parcel, leaseOwner, leaseExpiry,
			)
		},
	)
	require.NoError(t, err)

	// Confirm, so the inputs are marked spent — the state a buried
	// foreign spend later abandons.
	blockHash, header, merkle := blockContextFor(t, newAnchorTx, 1)
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			conf, burns, err := assetsStore.RebuildAnchorConfirm(
				ctx, q, newAnchorTx, blockHash, 600, 0, header,
				merkle, "",
			)
			if err != nil {
				return err
			}

			_, err = assetsStore.ApplyAnchorTxConfirm(
				ctx, q, conf, burns,
			)

			return err
		},
	)
	require.NoError(t, err)

	// The passive holding: model the confirmed re-anchor by extending
	// its file with a proof anchored in the transfer's transaction and
	// recording the passive reference.
	proof1 := randProof(t, passiveAsset.Asset)
	proof1.AnchorTx = *assetGen.anchorTxs[1]
	proof2 := randProof(t, passiveAsset.Asset)
	proof2.AnchorTx = *newAnchorTx
	passiveFile, err := proof.NewFile(proof.V0, *proof1, *proof2)
	require.NoError(t, err)
	var passiveBuf bytes.Buffer
	require.NoError(t, passiveFile.Encode(&passiveBuf))
	require.NoError(t, db.UpsertAssetProofByID(
		ctx, ProofUpdateByID{
			AssetID:   passiveDBID,
			ProofFile: passiveBuf.Bytes(),
		},
	))

	_, err = db.DB.ExecContext(
		ctx, "INSERT INTO passive_assets "+
			"(transfer_id, asset_id, new_anchor_utxo, "+
			"script_key, asset_version) "+
			"SELECT transfers.id, $1, "+
			"assets.anchor_utxo_id, "+
			"script_keys.tweaked_script_key, 0 "+
			"FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id, "+
			"asset_transfers transfers "+
			"WHERE assets.asset_id = $1 "+
			"AND transfers.anchor_txn_id IN "+
			"(SELECT txn_id FROM chain_txns "+
			"WHERE txid = $2)",
		passiveDBID, anchorTxHash[:],
	)
	require.NoError(t, err)

	var transferID int64
	err = db.DB.QueryRowContext(
		ctx, "SELECT id FROM asset_transfers "+
			"WHERE anchor_txn_id = (SELECT txn_id FROM chain_txns "+
			"WHERE txid = $1)", anchorTxHash[:],
	).Scan(&transferID)
	require.NoError(t, err)

	w := &rivalryWorld{
		inputPoint:  inputPoint,
		secondPoint: secondPoint,
		oldPassive:  oldPassive,
		inputDBID:   inputDBID,
		secondDBID:  secondDBID,
		passiveDBID: passiveDBID,
		transferID:  transferID,

		abandon: func(t *testing.T, foreclosure *wire.MsgTx) {
			err := executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					_, err := assetsStore.
						ApplyTransferAbandonment(
							ctx, q, anchorTxHash,
							foreclosure,
						)
					return err
				},
			)
			require.NoError(t, err)
		},
		unconfirm: func(t *testing.T) {
			err := executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					return assetsStore.
						ApplyAnchorTxUnconfirm(
							ctx, q, anchorTxHash,
						)
				},
			)
			require.NoError(t, err)
		},
		assetSpent: func(t *testing.T, dbID int64) bool {
			var spent bool
			err := db.DB.QueryRowContext(
				ctx, "SELECT spent FROM assets "+
					"WHERE asset_id = $1", dbID,
			).Scan(&spent)
			require.NoError(t, err)

			return spent
		},
		leaseHeld: func(t *testing.T, point wire.OutPoint) bool {
			pointBytes, err := encodeOutpoint(point)
			require.NoError(t, err)

			var held bool
			err = db.DB.QueryRowContext(
				ctx, "SELECT lease_owner IS NOT NULL "+
					"FROM managed_utxos "+
					"WHERE outpoint = $1", pointBytes,
			).Scan(&held)
			require.NoError(t, err)

			return held
		},
		superseded: func(t *testing.T, transferID int64) bool {
			var superseded bool
			err := db.DB.QueryRowContext(
				ctx, "SELECT superseded FROM "+
					"asset_transfers WHERE id = $1",
				transferID,
			).Scan(&superseded)
			require.NoError(t, err)

			return superseded
		},
		abandoned: func(t *testing.T, transferID int64) bool {
			var abandoned bool
			err := db.DB.QueryRowContext(
				ctx, "SELECT abandoned FROM "+
					"asset_transfers WHERE id = $1",
				transferID,
			).Scan(&abandoned)
			require.NoError(t, err)

			return abandoned
		},
		passiveProofs: func(t *testing.T) int {
			blob, err := db.AssetProofBlobByAssetID(
				ctx, passiveDBID,
			)
			require.NoError(t, err)
			file := &proof.File{}
			require.NoError(t, file.Decode(bytes.NewReader(blob)))

			return file.NumProofs()
		},
	}

	if !plantRival {
		return w
	}

	// A superseded rival spending the same inputs, its own anchor
	// still unconfirmed: the revival candidate.
	rivalTx := wire.NewMsgTx(2)
	rivalTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputPoint})
	if secondInput {
		rivalTx.AddTxIn(&wire.TxIn{PreviousOutPoint: secondPoint})
	}
	rivalTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    900,
	})
	rivalBytes, err := fn.Serialize(rivalTx)
	require.NoError(t, err)
	rivalHash := rivalTx.TxHash()
	_, err = db.UpsertChainTx(ctx, sqlc.UpsertChainTxParams{
		Txid:  rivalHash[:],
		RawTx: rivalBytes,
	})
	require.NoError(t, err)

	_, err = db.DB.ExecContext(
		ctx, "INSERT INTO asset_transfers "+
			"(height_hint, anchor_txn_id, transfer_time_unix, "+
			"superseded) "+
			"SELECT 1, txn_id, CURRENT_TIMESTAMP, TRUE "+
			"FROM chain_txns WHERE txid = $1", rivalHash[:],
	)
	require.NoError(t, err)
	err = db.DB.QueryRowContext(
		ctx, "SELECT id FROM asset_transfers ORDER BY id DESC LIMIT 1",
	).Scan(&w.rivalID)
	require.NoError(t, err)

	insertRivalInput := func(chainAsset *asset.ChainAsset,
		point wire.OutPoint) {

		pointBytes, err := encodeOutpoint(point)
		require.NoError(t, err)

		assetIDBytes := chainAsset.ID()
		err = db.InsertAssetTransferInput(
			ctx, sqlc.InsertAssetTransferInputParams{
				TransferID:  w.rivalID,
				AnchorPoint: pointBytes,
				AssetID:     assetIDBytes[:],
				ScriptKey: chainAsset.ScriptKey.PubKey.
					SerializeCompressed(),
				Amount: int64(chainAsset.Amount),
			},
		)
		require.NoError(t, err)
	}
	insertRivalInput(inputAsset, inputPoint)
	if secondInput {
		insertRivalInput(secondAsset, secondPoint)
	}

	// The rival confirms: the confirmation application over its
	// (output-less) transfer state, the way the chain deciding for
	// it after a re-organization would be applied.
	w.confirmRival = func(t *testing.T) {
		conf := &tapfreighter.AssetConfirmEvent{
			AnchorTXID:  rivalHash,
			BlockHash:   chainhash.Hash{0x77},
			BlockHeight: 601,
		}
		err := executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				_, err := assetsStore.ApplyAnchorTxConfirm(
					ctx, q, conf, nil,
				)

				return err
			},
		)
		require.NoError(t, err)
	}

	return w
}

// TestPorterAbandonmentForeclosure pins what compensation owes the
// foreclosing transaction's input set. The watcher derives Abandoned
// from any buried foreign spend — for tapchannel anchorings the
// forecloser is routinely a genuine third party — but the reversal
// queries can only see local transfers. An input the forecloser
// consumed is gone: un-spending it fabricates balance the chain
// assigned to someone else, a rival needing it can never confirm, and
// a passive holding restored to it is no longer ours. Inputs the
// forecloser did not touch reverse exactly as before, except that the
// lease is retained while a revived rival is still in flight to spend
// the input.
func TestPorterAbandonmentForeclosure(t *testing.T) {
	t.Parallel()

	// The chain gave the transfer's input and the passive's prior
	// anchor to the foreclosing transaction: nothing it consumed is
	// restored. The input stays spent and leased, the rival needing
	// it stays superseded, and the passive — its history truncated
	// to the outpoint the forecloser took — is marked spent.
	t.Run("foreclosed", func(t *testing.T) {
		t.Parallel()

		w := buildRivalryWorld(t, true, false)

		foreclosure := wire.NewMsgTx(2)
		foreclosure.AddTxIn(&wire.TxIn{
			PreviousOutPoint: w.inputPoint,
		})
		foreclosure.AddTxIn(&wire.TxIn{
			PreviousOutPoint: w.oldPassive,
		})
		foreclosure.AddTxOut(&wire.TxOut{
			PkScript: bytes.Repeat([]byte{0x03}, 34),
			Value:    800,
		})
		w.abandon(t, foreclosure)

		require.True(
			t, w.assetSpent(t, w.inputDBID),
			"foreclosed input restored: balance now counts an "+
				"asset a third party took",
		)
		require.True(t, w.leaseHeld(t, w.inputPoint))
		require.True(
			t, w.superseded(t, w.rivalID),
			"revived a rival whose input the forecloser "+
				"consumed; it can never confirm",
		)
		require.Equal(t, 1, w.passiveProofs(t))
		require.True(
			t, w.assetSpent(t, w.passiveDBID),
			"passive restored to a foreclosed outpoint left "+
				"unspent: balance counts a holding a third "+
				"party took",
		)
	})

	// The forecloser consumed one of two inputs the rival shares
	// with the transfer. The other input reverses as usual, but the
	// rival is not revived through it: one of its inputs is gone, so
	// its anchor can never confirm. Its flags stay as they are — it
	// is left superseded, not marked abandoned, since that flag
	// records a transfer's own compensation — and, with no live
	// claimant, the restored input's lease is released.
	t.Run("foreclosed shared input", func(t *testing.T) {
		t.Parallel()

		w := buildRivalryWorld(t, true, true)

		foreclosure := wire.NewMsgTx(2)
		foreclosure.AddTxIn(&wire.TxIn{
			PreviousOutPoint: w.inputPoint,
		})
		foreclosure.AddTxOut(&wire.TxOut{
			PkScript: bytes.Repeat([]byte{0x03}, 34),
			Value:    800,
		})
		w.abandon(t, foreclosure)

		require.True(t, w.assetSpent(t, w.inputDBID))
		require.True(t, w.leaseHeld(t, w.inputPoint))
		require.False(t, w.assetSpent(t, w.secondDBID))
		require.True(
			t, w.superseded(t, w.rivalID),
			"revived a rival through an untouched input while "+
				"the forecloser consumed another of its inputs",
		)
		require.False(t, w.abandoned(t, w.rivalID))
		require.False(
			t, w.leaseHeld(t, w.secondPoint),
			"input left leased with no live claimant",
		)
	})

	// A foreclosure that consumed none of the transfer's inputs
	// (or no known foreclosure at all) reverses everything: every
	// input un-spent, every lease released, passive restored as
	// ours.
	t.Run("untouched", func(t *testing.T) {
		t.Parallel()

		w := buildRivalryWorld(t, false, true)

		foreclosure := wire.NewMsgTx(2)
		foreclosure.AddTxIn(&wire.TxIn{
			PreviousOutPoint: test.RandOp(t),
		})
		w.abandon(t, foreclosure)

		require.False(t, w.assetSpent(t, w.inputDBID))
		require.False(t, w.assetSpent(t, w.secondDBID))
		require.False(t, w.leaseHeld(t, w.inputPoint))
		require.False(t, w.leaseHeld(t, w.secondPoint))
		require.Equal(t, 1, w.passiveProofs(t))
		require.False(t, w.assetSpent(t, w.passiveDBID))
	})

	// A revived rival is still in flight to spend the restored
	// inputs: every lease must outlive the abandonment, or a new
	// send can select an input from under the rival's replacement.
	// The rival shares both inputs, and revival is a per-transfer
	// flag flipped once — at whichever input is processed first —
	// so the lease decision must not be read off that step.
	t.Run("rival revived", func(t *testing.T) {
		t.Parallel()

		w := buildRivalryWorld(t, true, true)

		w.abandon(t, nil)

		require.False(t, w.assetSpent(t, w.inputDBID))
		require.False(t, w.assetSpent(t, w.secondDBID))
		require.False(t, w.superseded(t, w.rivalID))
		require.True(
			t, w.leaseHeld(t, w.inputPoint),
			"input unleased while the revived rival's anchor "+
				"is still in flight",
		)
		require.True(
			t, w.leaseHeld(t, w.secondPoint),
			"second input unleased while the revived rival's "+
				"anchor is still in flight: the rival was "+
				"revived at the first input, not this one",
		)
	})
}

// TestPorterSupersessionFollowsConfirmation pins the superseded flag
// to the chain's current decision between rivals. Supersession is
// entered when a rival confirms and only unconfirmed rivals are
// marked, so two transitions would otherwise leave the flag stale: a
// loser that confirms after the winner is re-organized out must lift
// its own flag, or it is skipped at startup and never completes; and
// a winner whose confirmation is withdrawn while the loser has since
// confirmed must enter supersession, or it is resumed at startup and
// rebroadcasts an anchor that can never confirm.
func TestPorterSupersessionFollowsConfirmation(t *testing.T) {
	t.Parallel()

	// The transfer's confirmation is re-organized out and the rival
	// it had superseded confirms instead: the rival becomes the live
	// form, the transfer the superseded one.
	t.Run("loser confirms after re-org", func(t *testing.T) {
		t.Parallel()

		w := buildRivalryWorld(t, true, false)

		w.unconfirm(t)
		require.False(
			t, w.superseded(t, w.transferID),
			"transfer superseded by an unconfirmed rival",
		)

		w.confirmRival(t)
		require.False(
			t, w.superseded(t, w.rivalID),
			"confirmed transfer left superseded: it is skipped "+
				"at startup and never completes",
		)
		require.True(t, w.superseded(t, w.transferID))
		require.False(t, w.abandoned(t, w.transferID))
	})

	// The rival confirms while the transfer's own confirmation still
	// stands; when that confirmation is then withdrawn, the transfer
	// is a rivalry loser and must not be resumed as pending.
	t.Run("confirmation withdrawn under a confirmed rival",
		func(t *testing.T) {
			t.Parallel()

			w := buildRivalryWorld(t, true, false)

			w.confirmRival(t)
			require.False(t, w.superseded(t, w.rivalID))
			require.False(t, w.superseded(t, w.transferID))

			w.unconfirm(t)
			require.True(
				t, w.superseded(t, w.transferID),
				"unconfirmed transfer left live under a "+
					"confirmed rival: it is resumed at "+
					"startup and rebroadcasts a doomed "+
					"anchor",
			)
			require.False(t, w.superseded(t, w.rivalID))
			require.False(t, w.abandoned(t, w.transferID))
		})
}
