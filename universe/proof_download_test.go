package universe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TestStitchProofsForDebugging is a test that can be used to fetch a partial
// starting proof file from a universe and append/stitch together additional
// proofs for debugging purposes. It is not meant to be run as part of the
// regular test suite, but can be used to debug issues locally or to manually
// fix proofs that failed for some reason.
// A potential workflow to fix failed proofs could look like this:
//   - Copy the new_proof_blob field from a failed transfer output into the
//     proof/testdata/proof.hex file.
//   - Run the TestProofVerification test to see what's wrong, manually fix what
//     needs to be fixed, then re-encode the proof and get the raw hex.
//   - Edit the outpoint/groupKeyBytes/assetIDBytes/scriptKeyBytes below and set
//     them to the last known proof in the universe that is right before the
//     failed proof.
//   - Find out in which block the transaction for the failed proof was included
//     in and then set the stitchMap to the block height and the raw hex string
//     of the manually fixed proof (or multiple proofs).
//   - Run the test and import the resulting proof file into the node.
func TestFetchProofFromUniverseForDebugging(t *testing.T) {
	// Comment this out for local debugging.
	t.Skipf("This test is for debugging purposes only.")

	// EDIT the following constants and variables:
	const (
		universeServer = "universe.lightning.finance:10029"
		bitcoindServer = "localhost:8332"
		bitcoindUser   = "lightning"
		bitcoindPass   = "lightning"
	)
	var (
		outpoint, _ = wire.NewOutPointFromString(
			"xxxx:0",
		)
		groupKeyBytes, _ = hex.DecodeString(
			"02xxxx",
		)
		assetIDBytes, _ = hex.DecodeString(
			"xxxxx",
		)
		scriptKeyBytes, _ = hex.DecodeString(
			"02xxxx",
		)
		// stitchMap is a map of block heights to the raw proof as a hex
		// dump that should be stitched into the proof file. We assume
		// that the proofs come from the output of a partial transfer
		// (field new_proof_blob on the "tapcli assets transfers"
		// output), where the proofs don't have a block height/header
		// set yet. Assuming the transaction already confirmed, we will
		// set the block height/header and stitch the proof into the
		// full file.
		stitchMap = map[int64]string{
			900115: "544150500004000000xxxxxxxxxxxxxxx",
			900116: "544150500004000000xxxxxxxxxxxxxxx",
		}
	)

	ctx := context.Background()
	tlsConfig := tls.Config{InsecureSkipVerify: true}
	transportCredentials := credentials.NewTLS(&tlsConfig)

	clientConn, err := grpc.NewClient(
		universeServer,
		grpc.WithTransportCredentials(transportCredentials),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		err := clientConn.Close()
		require.NoError(t, err)
	})

	src := unirpc.NewUniverseClient(clientConn)
	fetchUniProof := func(ctx context.Context,
		loc proof.Locator) (proof.Blob, error) {

		uniID := Identifier{
			AssetID: *loc.AssetID,
		}
		if loc.GroupKey != nil {
			uniID.GroupKey = loc.GroupKey
		}

		rpcUniID, err := marshalUniID(uniID)
		require.NoError(t, err)

		op := &unirpc.Outpoint{
			HashStr: loc.OutPoint.Hash.String(),
			Index:   int32(loc.OutPoint.Index),
		}
		scriptKeyBytes := loc.ScriptKey.SerializeCompressed()

		uniProof, err := src.QueryProof(ctx, &unirpc.UniverseKey{
			Id: rpcUniID,
			LeafKey: &unirpc.AssetKey{
				Outpoint: &unirpc.AssetKey_Op{
					Op: op,
				},
				ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
					ScriptKeyBytes: scriptKeyBytes,
				},
			},
		})
		if err != nil {
			return nil, err
		}

		return uniProof.AssetLeaf.Proof, nil
	}

	var (
		assetID      *asset.ID
		groupKey     *btcec.PublicKey
		scriptPubKey *btcec.PublicKey
	)

	if len(groupKeyBytes) > 0 {
		groupKey, err = btcec.ParsePubKey(groupKeyBytes)
		require.NoError(t, err)
	}
	if len(assetIDBytes) > 0 {
		assetID = new(asset.ID)
		copy(assetID[:], assetIDBytes)
	}

	scriptPubKey, err = btcec.ParsePubKey(scriptKeyBytes)
	require.NoError(t, err)

	locator := proof.Locator{
		OutPoint:  outpoint,
		AssetID:   assetID,
		GroupKey:  groupKey,
		ScriptKey: *scriptPubKey,
	}

	fullFile, err := proof.FetchProofProvenance(
		ctx, nil, locator, fetchUniProof,
	)
	require.NoError(t, err)

	for i := uint32(0); i < uint32(fullFile.NumProofs()); i++ {
		p, err := fullFile.ProofAt(i)
		require.NoError(t, err)

		// EDIT this or comment out according to your needs. In this
		// specific case, the proofs were from a channel commitment and
		// sweep transaction, which didn't use V1 proofs yet. So we
		// needed to manually remove the STXO proofs to allow them to
		// be validated.
		p.InclusionProof.CommitmentProof.STXOProofs = nil
		for idx := range p.ExclusionProofs {
			if p.ExclusionProofs[idx].CommitmentProof == nil {
				continue
			}

			p.ExclusionProofs[idx].CommitmentProof.STXOProofs = nil
		}

		err = fullFile.ReplaceProofAt(i, *p)
		require.NoError(t, err)
	}

	bitcoindCfg := &chain.BitcoindConfig{
		ChainParams: &chaincfg.MainNetParams,
		Host:        bitcoindServer,
		User:        bitcoindUser,
		Pass:        bitcoindPass,
		Dialer: func(s string) (net.Conn, error) {
			dialer := &tor.ClearNet{}
			return dialer.Dial("tcp", s, time.Minute)
		},
		PrunedModeMaxPeers: 10,
		PollingConfig: &chain.PollingConfig{
			BlockPollingInterval:    time.Minute,
			TxPollingInterval:       time.Minute,
			TxPollingIntervalJitter: lncfg.DefaultTxPollingJitter,
		},
	}

	// Establish the connection to bitcoind and create the clients
	// required for our relevant subsystems.
	bitcoindConn, err := chain.NewBitcoindConn(bitcoindCfg)
	require.NoError(t, err)
	client := bitcoindConn.NewBitcoindClient()

	for blockHeight, proofHex := range stitchMap {
		proofBytes, err := hex.DecodeString(proofHex)
		require.NoError(t, err)

		stitchProof, err := proof.Decode(proofBytes)
		require.NoError(t, err)
		stitchProof.Version = 0

		blockHash, err := client.GetBlockHash(blockHeight)
		require.NoError(t, err)

		block, err := client.GetBlock(blockHash)
		require.NoError(t, err)

		stitchProof.BlockHeight = uint32(blockHeight)
		stitchProof.BlockHeader = block.Header

		idx := -1
		for i, tx := range block.Transactions {
			if tx.TxHash() == stitchProof.OutPoint().Hash {
				idx = i
				break
			}
		}
		require.GreaterOrEqual(t, idx, 0, "tx not found in block")

		merkleProof, err := proof.NewTxMerkleProof(
			block.Transactions, idx,
		)
		require.NoError(t, err)

		stitchProof.TxMerkleProof = *merkleProof

		err = fullFile.AppendProof(*stitchProof)
		require.NoError(t, err)

		var buf bytes.Buffer
		err = stitchProof.Encode(&buf)
		require.NoError(t, err)
		t.Logf("Stich proof for block %d: %x", blockHeight, buf.Bytes())
	}

	_, err = fullFile.Verify(ctx, proof.MockVerifierCtx)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = fullFile.Encode(&buf)
	require.NoError(t, err)

	// Write the full file to disk.
	err = os.MkdirAll("testdata", 0755)
	require.NoError(t, err)
	err = os.WriteFile("testdata/downloaded.proof", buf.Bytes(), 0644)
	require.NoError(t, err)
}

// marshalUniProofType marshals the universe proof type into the RPC
// counterpart. Copied from the main package to avoid circular dependency.
func marshalUniProofType(
	proofType ProofType) (unirpc.ProofType, error) {

	switch proofType {
	case ProofTypeUnspecified:
		return unirpc.ProofType_PROOF_TYPE_UNSPECIFIED, nil
	case ProofTypeIssuance:
		return unirpc.ProofType_PROOF_TYPE_ISSUANCE, nil
	case ProofTypeTransfer:
		return unirpc.ProofType_PROOF_TYPE_TRANSFER, nil

	default:
		return 0, fmt.Errorf("unknown universe proof type: %v",
			proofType)
	}
}

// marshalUniID marshals the universe ID into the RPC counterpart. Copied from
// the main package to avoid circular dependency.
func marshalUniID(id Identifier) (*unirpc.ID, error) {
	var uniID unirpc.ID

	if id.GroupKey != nil {
		uniID.Id = &unirpc.ID_GroupKey{
			GroupKey: schnorr.SerializePubKey(id.GroupKey),
		}
	} else {
		uniID.Id = &unirpc.ID_AssetId{
			AssetId: id.AssetID[:],
		}
	}

	proofTypeRpc, err := marshalUniProofType(id.ProofType)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal proof type: %w", err)
	}
	uniID.ProofType = proofTypeRpc

	return &uniID, nil
}
