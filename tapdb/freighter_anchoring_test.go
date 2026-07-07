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
				return assetsStore.ApplyTransferAbandonment(
					ctx, q, anchorTxHash,
				)
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
			return assetsStore.ApplyTransferAbandonment(
				ctx, q, anchorTxHash,
			)
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
