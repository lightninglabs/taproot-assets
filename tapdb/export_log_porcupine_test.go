package tapdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type exportLogOperation uint8

const (
	exportLogConfirm exportLogOperation = iota
	exportLogDeliverProof
	exportLogQuery
	exportLogQueryPending
)

type exportLogInput struct {
	op exportLogOperation
}

type exportLogOutput struct {
	found     bool
	confirmed bool
	delivered bool
	failed    bool
}

type exportLogState struct {
	confirmed bool
	delivered bool
}

var exportLogModel = porcupine.Model{
	Init: func() interface{} {
		return exportLogState{}
	},
	Step: func(state, input, output interface{}) (bool, interface{}) {
		current := state.(exportLogState)
		in := input.(exportLogInput)
		out := output.(exportLogOutput)
		next := current

		switch in.op {
		case exportLogConfirm:
			if out.failed {
				return false, current
			}
			next.confirmed = true

		case exportLogDeliverProof:
			if out.failed {
				return false, current
			}
			next.delivered = true

		case exportLogQuery:
			valid := !out.failed && out.found &&
				out.confirmed == current.confirmed &&
				out.delivered == current.delivered
			return valid, current

		case exportLogQueryPending:
			expected := !current.confirmed || !current.delivered
			return !out.failed && out.found == expected, current

		default:
			return false, current
		}

		return true, next
	},
	Equal: func(state1, state2 interface{}) bool {
		return state1.(exportLogState) == state2.(exportLogState)
	},
	DescribeOperation: func(input, output interface{}) string {
		in := input.(exportLogInput)
		out := output.(exportLogOutput)
		return fmt.Sprintf(
			"op=%d -> found=%v, confirmed=%v, delivered=%v, "+
				"failed=%v", in.op, out.found, out.confirmed,
			out.delivered, out.failed,
		)
	},
}

type exportLogFixture struct {
	store            *AssetStore
	anchorHash       chainhash.Hash
	confirmation     tapfreighter.AssetConfirmEvent
	deliveryOutpoint wire.OutPoint
	deliveryPosition uint64
}

func newExportLogFixture(t *testing.T) *exportLogFixture {
	t.Helper()

	_, store, _ := newAssetStore(t)
	ctx := context.Background()
	targetScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetVersion := asset.V1
	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, store, []assetDesc{{
		assetGen:     assetGen.assetGens[0],
		anchorPoint:  assetGen.anchorPoints[0],
		scriptKey:    &targetScriptKey,
		amt:          16,
		assetVersion: &assetVersion,
	}})

	allAssets, err := store.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, 1)
	inputAsset := allAssets[0]

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{SignatureScript: []byte{}})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34), Value: 1000,
	})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34), Value: 1000,
	})
	anchorHash := anchorTx.TxHash()

	firstScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(rand.Int31()),
			Index:  uint32(rand.Int31()),
		},
	})
	secondScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(rand.Int31()),
			Index:  uint32(rand.Int31()),
		},
	})

	firstAsset := inputAsset.Copy()
	firstAsset.ScriptKey = firstScriptKey
	firstProof := randProof(t, firstAsset)
	firstProofBytes, err := firstProof.Bytes()
	require.NoError(t, err)

	secondAsset := inputAsset.Copy()
	secondAsset.ScriptKey = secondScriptKey
	secondProof := randProof(t, secondAsset)
	secondProofBytes, err := secondProof.Bytes()
	require.NoError(t, err)

	witness := asset.Witness{
		PrevID: &asset.PrevID{}, TxWitness: [][]byte{{0x01}, {0x02}},
	}
	rootHash := sha256.Sum256([]byte("porcupine-export-log"))
	root := mssmt.NewComputedNode(rootHash, 16)
	firstOutpoint := wire.OutPoint{Hash: anchorHash, Index: 0}
	secondOutpoint := wire.OutPoint{Hash: anchorHash, Index: 1}

	parcel := &tapfreighter.OutboundParcel{
		AnchorTx: anchorTx, AnchorTxHeightHint: 1450, ChainFees: 100,
		Inputs: []tapfreighter.TransferInput{{
			PrevID: asset.PrevID{
				OutPoint: assetGen.anchorPoints[0],
				ID:       inputAsset.ID(),
				ScriptKey: asset.ToSerialized(
					inputAsset.ScriptKey.PubKey,
				),
			},
			Amount: inputAsset.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor: tapfreighter.Anchor{
				OutPoint: firstOutpoint,
				Value:    1000,
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
				},
				TaprootAssetRoot: bytes.Repeat(
					[]byte{0x01}, 32,
				),
				MerkleRoot: bytes.Repeat([]byte{0x01}, 32),
				PkScript:   anchorTx.TxOut[0].PkScript,
			},
			ScriptKey:           firstScriptKey,
			ScriptKeyLocal:      true,
			Amount:              9,
			WitnessData:         []asset.Witness{witness},
			SplitCommitmentRoot: root,
			AssetVersion:        asset.V1,
			ProofSuffix:         firstProofBytes,
			ProofCourierAddr: []byte(
				"universerpc://localhost:10009",
			),
			ProofDeliveryComplete: fn.Some(false),
			Position:              0,
		}, {
			Anchor: tapfreighter.Anchor{
				OutPoint: secondOutpoint,
				Value:    1000,
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
				},
				TaprootAssetRoot: bytes.Repeat(
					[]byte{0x02}, 32,
				),
				MerkleRoot: bytes.Repeat([]byte{0x02}, 32),
				PkScript:   anchorTx.TxOut[1].PkScript,
			},
			ScriptKey:           secondScriptKey,
			ScriptKeyLocal:      true,
			Amount:              7,
			WitnessData:         []asset.Witness{witness},
			SplitCommitmentRoot: root,
			AssetVersion:        asset.V1,
			ProofSuffix:         secondProofBytes,
			Position:            1,
		}},
	}

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	err = store.LogPendingParcel(
		ctx, parcel, leaseOwner, time.Now().Add(time.Hour),
	)
	require.NoError(t, err)

	assetID := inputAsset.ID()
	firstIdentifier := tapfreighter.NewOutputIdentifier(
		assetID, 0, *firstScriptKey.PubKey,
	)
	secondIdentifier := tapfreighter.NewOutputIdentifier(
		assetID, 0, *secondScriptKey.PubKey,
	)
	blockHash := chainhash.Hash(sha256.Sum256([]byte("confirmed")))
	finalProofs := map[tapfreighter.OutputIdentifier]*proof.AnnotatedProof{
		firstIdentifier: {
			Locator: proof.Locator{
				AssetID:   &assetID,
				ScriptKey: *firstScriptKey.PubKey,
			},
			Blob: firstProofBytes,
		},
		secondIdentifier: {
			Locator: proof.Locator{
				AssetID:   &assetID,
				ScriptKey: *secondScriptKey.PubKey,
			},
			Blob: secondProofBytes,
		},
	}

	return &exportLogFixture{
		store:            store,
		anchorHash:       anchorHash,
		deliveryOutpoint: firstOutpoint,
		deliveryPosition: 0,
		confirmation: tapfreighter.AssetConfirmEvent{
			AnchorTXID:  anchorHash,
			BlockHash:   blockHash,
			BlockHeight: 100,
			TxIndex:     1,
			FinalProofs: finalProofs,
		},
	}
}

func executeExportLogOperation(fixture *exportLogFixture,
	in exportLogInput) exportLogOutput {

	ctx := context.Background()
	switch in.op {
	case exportLogConfirm:
		err := fixture.store.LogAnchorTxConfirm(
			ctx, &fixture.confirmation, nil,
		)
		return exportLogOutput{failed: err != nil}

	case exportLogDeliverProof:
		err := fixture.store.ConfirmProofDelivery(
			ctx, fixture.deliveryOutpoint, fixture.deliveryPosition,
		)
		return exportLogOutput{failed: err != nil}

	case exportLogQuery:
		parcels, err := fixture.store.QueryParcels(
			ctx, &fixture.anchorHash, false,
		)
		if err != nil || len(parcels) != 1 {
			return exportLogOutput{failed: true}
		}
		parcel := parcels[0]
		return exportLogOutput{
			found:     true,
			confirmed: parcel.AnchorTxBlockHash.IsSome(),
			delivered: parcel.Outputs[0].ProofDeliveryComplete.
				UnwrapOr(false),
		}

	case exportLogQueryPending:
		parcels, err := fixture.store.QueryParcels(
			ctx, &fixture.anchorHash, true,
		)
		return exportLogOutput{
			found: len(parcels) == 1, failed: err != nil,
		}

	default:
		return exportLogOutput{failed: true}
	}
}

func executeExportLogHistory(fixture *exportLogFixture,
	clients [][]exportLogInput) []porcupine.Operation {

	var operationCount int
	for _, operations := range clients {
		operationCount += len(operations)
	}

	var (
		clock   atomic.Int64
		wg      sync.WaitGroup
		start   = make(chan struct{})
		history = make(chan porcupine.Operation, operationCount)
	)
	for clientID, operations := range clients {
		clientID := clientID
		operations := operations
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for _, input := range operations {
				call := clock.Add(1)
				output := executeExportLogOperation(
					fixture, input,
				)
				ret := clock.Add(1)
				history <- porcupine.Operation{
					ClientId: clientID,
					Input:    input,
					Call:     call,
					Output:   output,
					Return:   ret,
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(history)

	result := make([]porcupine.Operation, 0, operationCount)
	for operation := range history {
		result = append(result, operation)
	}

	return result
}

// TestExportLogLinearizability checks that confirmation, proof delivery, and
// queries expose one valid atomic ordering through the production SQL store.
func TestExportLogLinearizability(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		queryClients := rapid.IntRange(2, 4).Draw(rt, "query_clients")
		clients := make([][]exportLogInput, queryClients+2)
		clients[0] = []exportLogInput{{op: exportLogConfirm}}
		clients[1] = []exportLogInput{{op: exportLogDeliverProof}}
		for clientID := 2; clientID < len(clients); clientID++ {
			queryCount := rapid.IntRange(1, 3).Draw(
				rt, fmt.Sprintf("client_%d_queries", clientID),
			)
			clients[clientID] = make([]exportLogInput, queryCount)
			for operationID := range clients[clientID] {
				pending := rapid.Bool().Draw(
					rt, fmt.Sprintf(
						"client_%d_query_%d_pending",
						clientID, operationID,
					),
				)
				op := exportLogQuery
				if pending {
					op = exportLogQueryPending
				}
				clients[clientID][operationID] = exportLogInput{
					op: op,
				}
			}
		}

		history := executeExportLogHistory(
			newExportLogFixture(t), clients,
		)
		result := porcupine.CheckOperationsTimeout(
			exportLogModel, history, 5*time.Second,
		)
		if result != porcupine.Ok {
			rt.Fatalf("export log history is not linearizable: "+
				"%v", result)
		}
	})
}

// TestExportLogModelRejectsPrematureCompletion proves that the model rejects
// a parcel disappearing before both confirmation and proof delivery finish.
func TestExportLogModelRejectsPrematureCompletion(t *testing.T) {
	t.Parallel()

	history := []porcupine.Operation{{
		ClientId: 0,
		Input:    exportLogInput{op: exportLogQueryPending},
		Call:     1,
		Output:   exportLogOutput{found: false},
		Return:   2,
	}}
	result := porcupine.CheckOperationsTimeout(
		exportLogModel, history, time.Second,
	)
	require.Equal(t, porcupine.Illegal, result)
}
