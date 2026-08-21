//nolint:lll
package itest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/rpc"
	"github.com/stretchr/testify/require"
)

type customAnchorMuSig2SigningEvidence struct {
	ParticipantPubKeys []string `json:"participant_pubkeys"`
	PublicNonces       []string `json:"public_nonces"`
	PartialSignatures  []string `json:"partial_signatures"`
	FinalSignature     string   `json:"final_signature"`
}

const (
	customAnchorUTXOKeyDomain             = "M10-ISSUE721-UTXO-KEY-V1\x00"
	customAnchorUTXOLeafDomain            = "M10-ISSUE721-UTXO-LEAF-V1\x00"
	customAnchorUTXOEmptyDomain           = "M10-ISSUE721-UTXO-EMPTY-V1\x00"
	customAnchorUTXONodeDomain            = "M10-ISSUE721-UTXO-NODE-V1\x00"
	customAnchorAuthorityCommitmentDomain = "M10-ISSUE721-AUTHORITY-COMMITMENT-V1\x00"
	customAnchorAuthorityTag              = "M10-ISSUE721-AUTHORITY-V1"
)

type customAnchorOutpointEvidence struct {
	TxID        string `json:"txid"`
	OutputIndex uint32 `json:"output_index"`
}

type customAnchorWalletLeafEvidence struct {
	Outpoint customAnchorOutpointEvidence `json:"outpoint"`
	Value    uint64                       `json:"value_sat"`
	Script   string                       `json:"script_pubkey"`
}

type customAnchorSparseProofEvidence struct {
	Key      string                          `json:"key"`
	Leaf     *customAnchorWalletLeafEvidence `json:"leaf,omitempty"`
	Siblings []string                        `json:"siblings_leaf_to_root"`
}

type customAnchorWalletQueryEvidence struct {
	MinConfirmations int32  `json:"min_confirmations"`
	MaxConfirmations int32  `json:"max_confirmations"`
	Account          string `json:"account"`
	UnconfirmedOnly  bool   `json:"unconfirmed_only"`
}

type customAnchorWalletCommitmentEvidence struct {
	Algorithm                 string                            `json:"algorithm"`
	KeyEncoding               string                            `json:"key_encoding"`
	LeafEncoding              string                            `json:"leaf_encoding"`
	TreeEncoding              string                            `json:"tree_encoding"`
	Query                     customAnchorWalletQueryEvidence   `json:"query"`
	Count                     uint64                            `json:"count"`
	Root                      string                            `json:"root"`
	FeeInputMembership        []customAnchorSparseProofEvidence `json:"fee_input_membership"`
	ForeignInputNonMembership customAnchorSparseProofEvidence   `json:"foreign_input_non_membership"`
}

type customAnchorKeyLocatorEvidence struct {
	Family int32 `json:"family"`
	Index  int32 `json:"index"`
}

type customAnchorAuthorityPoPEvidence struct {
	Algorithm          string                         `json:"algorithm"`
	Tag                string                         `json:"tag"`
	CommitmentEncoding string                         `json:"commitment_encoding"`
	Locator            customAnchorKeyLocatorEvidence `json:"locator"`
	PublicKey          string                         `json:"public_key_xonly"`
	Commitment         string                         `json:"commitment"`
	Signature          string                         `json:"signature"`
}

type customAnchorChainBlockEvidence struct {
	Height   uint32 `json:"height"`
	Hash     string `json:"hash"`
	RawBlock string `json:"raw_block"`
}

type customAnchorChainEvidence struct {
	Network     string                           `json:"network"`
	StartHeight uint32                           `json:"start_height"`
	TipHeight   uint32                           `json:"tip_height"`
	TipHash     string                           `json:"tip_hash"`
	Blocks      []customAnchorChainBlockEvidence `json:"blocks"`
}

type customAnchorAuthorityEvidence struct {
	AliceIdentityPubKey string                               `json:"alice_identity_pubkey"`
	WalletUTXO          customAnchorWalletCommitmentEvidence `json:"wallet_utxo_commitment"`
	AnchorKeyPoP        customAnchorAuthorityPoPEvidence     `json:"anchor_key_pop"`
	Chain               customAnchorChainEvidence            `json:"chain"`
}

type customAnchorSparseTree struct {
	leaves   map[[32]byte]customAnchorWalletLeafEvidence
	levels   [257]map[[32]byte][32]byte
	defaults [257][32]byte
}

type customAnchorMuSig2Evidence struct {
	Schema                   string                            `json:"schema"`
	CampaignID               string                            `json:"campaign_id"`
	CohortID                 string                            `json:"cohort_id,omitempty"`
	ProducerBinarySHA256     string                            `json:"producer_binary_sha256"`
	Version                  uint32                            `json:"version"`
	ForeignFundingTx         string                            `json:"foreign_funding_tx"`
	ForeignFundingBlock      string                            `json:"foreign_funding_block"`
	ForeignFundingBlockHash  string                            `json:"foreign_funding_block_hash"`
	ForeignFundingTxIndex    uint32                            `json:"foreign_funding_tx_index"`
	ForeignGenesisOutpoint   string                            `json:"foreign_genesis_outpoint"`
	ForeignPrevoutValue      int64                             `json:"foreign_prevout_value"`
	ForeignPrevoutScript     string                            `json:"foreign_prevout_script"`
	SuccessorOutputIndex     uint32                            `json:"successor_output_index"`
	SuccessorValue           int64                             `json:"successor_value"`
	SuccessorScript          string                            `json:"successor_script"`
	AssetAnchorOutputIndex   uint32                            `json:"asset_anchor_output_index"`
	AssetAnchorValue         int64                             `json:"asset_anchor_value"`
	AssetAnchorInternalKey   string                            `json:"asset_anchor_internal_key"`
	AssetAnchorKeyFamily     int32                             `json:"asset_anchor_key_family"`
	AssetAnchorKeyIndex      int32                             `json:"asset_anchor_key_index"`
	FundBatchAnchorPSBT      string                            `json:"fund_batch_anchor_psbt"`
	FundBatchAnchorIndex     uint32                            `json:"fund_batch_anchor_index"`
	FundBatchChangeIndex     int32                             `json:"fund_batch_change_index"`
	ChangeOutputIndex        int32                             `json:"change_output_index"`
	TemplatePSBT             string                            `json:"template_psbt"`
	FundedPSBT               string                            `json:"funded_psbt"`
	PreparedPSBT             string                            `json:"prepared_psbt"`
	ExternalFinalizedPSBT    string                            `json:"external_finalized_psbt"`
	WalletSignedPSBT         string                            `json:"wallet_signed_psbt"`
	WalletSignedInputIndexes []uint32                          `json:"wallet_signed_input_indexes"`
	FinalizedPSBT            string                            `json:"finalized_psbt"`
	FinalTransaction         string                            `json:"final_transaction"`
	MintTransactionID        string                            `json:"mint_transaction_id"`
	MintBlockHash            string                            `json:"mint_block_hash"`
	MintAssetID              string                            `json:"mint_asset_id"`
	MintProof                string                            `json:"mint_proof"`
	PostSpendTransactionID   string                            `json:"post_spend_transaction_id"`
	PostSpendTransaction     string                            `json:"post_spend_transaction"`
	PostSpendProof           string                            `json:"post_spend_proof"`
	MuSig2Signing            customAnchorMuSig2SigningEvidence `json:"musig2_signing"`
	Authority                customAnchorAuthorityEvidence     `json:"authority"`
}

// testMintCustomAnchorMuSig2Psbt proves the full MINT-10 transaction shape:
// genesis input zero is a genuinely foreign, leafless two-party MuSig2 spend;
// a wallet input pays fees; output zero preserves the caller's collateral
// successor; and a distinct wallet-owned output carries the asset commitment.
func testMintCustomAnchorMuSig2Psbt(t *harnessTest) {
	var (
		ctx       = context.Background()
		aliceTapd = t.tapd
		aliceLnd  = t.tapd.cfg.LndNode
		miner     = t.lndHarness.Miner()
	)

	bobLnd := t.lndHarness.NewNodeWithCoins("custom-musig-bob", nil)
	carolLnd := t.lndHarness.NewNodeWithCoins("custom-musig-carol", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	bobKey := deriveMuSig2Key(t.t, bobLnd.RPC)
	carolKey := deriveMuSig2Key(t.t, carolLnd.RPC)
	aggregateKey, err := input.MuSig2CombineKeys(
		input.MuSig2Version100RC2,
		[]*btcec.PublicKey{bobKey.PubKey, carolKey.PubKey}, true,
		&input.MuSig2Tweaks{TaprootBIP0086Tweak: true},
	)
	require.NoError(t.t, err)
	foreignScript, err := txscript.PayToTaprootScript(aggregateKey.FinalKey)
	require.NoError(t.t, err)

	const foreignValue = int64(100_000)
	foreignTxID := miner.SendOutput(&wire.TxOut{
		Value: foreignValue, PkScript: foreignScript,
	}, btcutil.Amount(1_000))
	foreignFundingBlock := MineBlocks(t.t, miner, 1, 1)[0]
	foreignFundingBestHash, foreignFundingHeight := miner.GetBestBlock()
	require.Equal(t.t, foreignFundingBlock.BlockHash(),
		*foreignFundingBestHash)
	foreignFundingTxIndex := -1
	for idx, blockTx := range foreignFundingBlock.Transactions {
		if blockTx.TxHash() == *foreignTxID {
			foreignFundingTxIndex = idx
			break
		}
	}
	require.NotEqual(t.t, -1, foreignFundingTxIndex)
	foreignFundingTx := miner.GetRawTransaction(*foreignTxID).MsgTx()
	foreignOutputIndex := -1
	for idx, txOut := range foreignFundingTx.TxOut {
		if txOut.Value == foreignValue &&
			bytes.Equal(txOut.PkScript, foreignScript) {

			foreignOutputIndex = idx
			break
		}
	}
	require.NotEqual(t.t, -1, foreignOutputIndex)
	foreignOutpoint := wire.OutPoint{
		Hash: *foreignTxID, Index: uint32(foreignOutputIndex),
	}
	foreignPrevOut := foreignFundingTx.TxOut[foreignOutputIndex]

	mintReq := CopyRequest(simpleAssets[0])
	mintReq.Asset.Name = "issue-721-foreign-musig2-itest"
	mintReq.Asset.Amount = 100
	mintReqs := []*mintrpc.MintAssetRequest{mintReq}
	BuildMintingBatch(t.t, aliceTapd, mintReqs)

	anchorKeyResp := aliceLnd.RPC.DeriveNextKey(&walletrpc.KeyReq{
		KeyFamily: int32(asset.TaprootAssetsKeyFamily),
	})
	anchorInternalKey, err := btcec.ParsePubKey(anchorKeyResp.RawKeyBytes)
	require.NoError(t.t, err)
	anchorPlaceholderKey := txscript.ComputeTaprootKeyNoScript(
		anchorInternalKey,
	)
	anchorPlaceholderScript, err := txscript.PayToTaprootScript(
		anchorPlaceholderKey,
	)
	require.NoError(t.t, err)
	anchorKeyDesc := keychain.KeyDescriptor{
		PubKey: anchorInternalKey,
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(anchorKeyResp.KeyLoc.KeyFamily),
			Index:  uint32(anchorKeyResp.KeyLoc.KeyIndex),
		},
	}
	anchorDerivation, anchorTaprootDerivation :=
		tappsbt.Bip32DerivationFromKeyDesc(
			anchorKeyDesc, harnessNetParams.HDCoinType,
		)

	const (
		successorValue = foreignValue
		anchorValue    = int64(10_000)
		successorIndex = 0
		anchorIndex    = 1
	)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: foreignOutpoint})
	tx.AddTxOut(&wire.TxOut{
		Value: successorValue, PkScript: foreignScript,
	})
	tx.AddTxOut(&wire.TxOut{
		Value: anchorValue, PkScript: anchorPlaceholderScript,
	})
	template, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t.t, err)
	template.Inputs[0].WitnessUtxo = foreignPrevOut
	template.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(
		aggregateKey.PreTweakedKey,
	)
	template.Inputs[0].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{{
			XOnlyPubKey: schnorr.SerializePubKey(
				aggregateKey.PreTweakedKey,
			),
		}}
	template.Inputs[0].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x50}, Value: []byte("foreign-two-party-musig2"),
	}}
	template.Outputs[successorIndex].TaprootInternalKey =
		schnorr.SerializePubKey(aggregateKey.PreTweakedKey)
	template.Outputs[successorIndex].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x51}, Value: []byte("preserved-collateral-successor"),
	}}
	template.Outputs[anchorIndex].Bip32Derivation =
		[]*psbt.Bip32Derivation{anchorDerivation}
	template.Outputs[anchorIndex].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{anchorTaprootDerivation}
	template.Outputs[anchorIndex].TaprootInternalKey =
		anchorTaprootDerivation.XOnlyPubKey
	template.Outputs[anchorIndex].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x52}, Value: []byte("wallet-owned-asset-anchor"),
	}}

	templateBytes, err := fn.Serialize(template)
	require.NoError(t.t, err)
	normalizedTemplate, err := psbt.NewFromRawBytes(
		bytes.NewReader(templateBytes), false,
	)
	require.NoError(t.t, err)

	// Commit to Alice's complete, non-paginated WalletKit UTXO view before
	// funding. The evidence only discloses the selected fee leaves and the
	// foreign empty leaf; it never exports addresses or the full inventory.
	walletQuery := customAnchorWalletQueryEvidence{
		MinConfirmations: 0,
		MaxConfirmations: math.MaxInt32,
		Account:          "",
		UnconfirmedOnly:  false,
	}
	walletSnapshot := aliceLnd.RPC.ListUnspent(
		&walletrpc.ListUnspentRequest{
			MinConfs:        walletQuery.MinConfirmations,
			MaxConfs:        walletQuery.MaxConfirmations,
			Account:         walletQuery.Account,
			UnconfirmedOnly: walletQuery.UnconfirmedOnly,
		},
	)
	walletTree, err := newCustomAnchorSparseTree(walletSnapshot.Utxos)
	require.NoError(t.t, err)

	fundResp := aliceLnd.RPC.FundPsbt(&walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_CoinSelect{
			CoinSelect: &walletrpc.PsbtCoinSelect{
				Psbt: templateBytes,
				ChangeOutput: &walletrpc.PsbtCoinSelect_Add{
					Add: true,
				},
			},
		},
		Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: 2,
		},
		MinConfs:    1,
		ChangeType:  walletrpc.ChangeAddressType_CHANGE_ADDRESS_TYPE_P2TR,
		MaxFeeRatio: 1,
	})
	require.NotEmpty(t.t, fundResp.LockedUtxos)
	require.GreaterOrEqual(t.t, fundResp.ChangeOutputIndex, int32(2))
	fundedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)
	require.Greater(t.t, len(fundedPacket.Inputs), 1)
	require.Equal(t.t, foreignOutpoint,
		fundedPacket.UnsignedTx.TxIn[0].PreviousOutPoint)
	require.Equal(t.t, normalizedTemplate.Inputs[0], fundedPacket.Inputs[0])
	require.Equal(t.t, normalizedTemplate.UnsignedTx.TxOut[successorIndex],
		fundedPacket.UnsignedTx.TxOut[successorIndex])
	require.Equal(t.t, normalizedTemplate.Outputs[successorIndex],
		fundedPacket.Outputs[successorIndex])
	require.Equal(t.t, normalizedTemplate.UnsignedTx.TxOut[anchorIndex],
		fundedPacket.UnsignedTx.TxOut[anchorIndex])
	fee, err := fundedPacket.GetTxFee()
	require.NoError(t.t, err)
	var walletInputValue int64
	for idx := 1; idx < len(fundedPacket.Inputs); idx++ {
		require.NotNil(t.t, fundedPacket.Inputs[idx].WitnessUtxo)
		walletInputValue += fundedPacket.Inputs[idx].WitnessUtxo.Value
	}
	var walletChangeValue int64
	for idx := 2; idx < len(fundedPacket.UnsignedTx.TxOut); idx++ {
		walletChangeValue += fundedPacket.UnsignedTx.TxOut[idx].Value
	}
	require.Equal(t.t, anchorValue+walletChangeValue+int64(fee),
		walletInputValue)

	feeMembership := make([]customAnchorSparseProofEvidence, 0,
		len(fundedPacket.Inputs)-1)
	for idx := 1; idx < len(fundedPacket.Inputs); idx++ {
		proof, err := walletTree.proof(
			fundedPacket.UnsignedTx.TxIn[idx].PreviousOutPoint, true,
		)
		require.NoError(t.t, err)
		require.NotNil(t.t, proof.Leaf)
		require.Equal(t.t,
			customAnchorOutpointEvidenceFromWire(
				fundedPacket.UnsignedTx.TxIn[idx].PreviousOutPoint,
			), proof.Leaf.Outpoint,
		)
		require.Equal(t.t,
			uint64(fundedPacket.Inputs[idx].WitnessUtxo.Value),
			proof.Leaf.Value,
		)
		require.Equal(t.t, hex.EncodeToString(
			fundedPacket.Inputs[idx].WitnessUtxo.PkScript,
		), proof.Leaf.Script)
		feeMembership = append(feeMembership, proof)
	}
	foreignNonMembership, err := walletTree.proof(foreignOutpoint, false)
	require.NoError(t.t, err)
	foreignKey, err := customAnchorSparseKey(
		customAnchorOutpointEvidenceFromWire(foreignOutpoint),
	)
	require.NoError(t.t, err)
	require.Equal(t.t, hex.EncodeToString(foreignKey[:]),
		foreignNonMembership.Key)
	walletRoot := walletTree.root()
	walletEvidence := customAnchorWalletCommitmentEvidence{
		Algorithm: "sha256-sparse-merkle-256-v1",
		KeyEncoding: "SHA256(M10-ISSUE721-UTXO-KEY-V1\\0 || " +
			"txid_display_bytes_be[32] || vout_u32be)",
		LeafEncoding: "SHA256(M10-ISSUE721-UTXO-LEAF-V1\\0 || " +
			"key[32] || value_u64be || script_len_u32be || script)",
		TreeEncoding: "256 levels, key bits MSB-first from root; " +
			"empty=SHA256(M10-ISSUE721-UTXO-EMPTY-V1\\0); " +
			"node=SHA256(M10-ISSUE721-UTXO-NODE-V1\\0 || left || " +
			"right); proof siblings are leaf-to-root and proof[i] " +
			"uses key bit 255-i",
		Query:                     walletQuery,
		Count:                     uint64(len(walletSnapshot.Utxos)),
		Root:                      hex.EncodeToString(walletRoot[:]),
		FeeInputMembership:        feeMembership,
		ForeignInputNonMembership: foreignNonMembership,
	}

	for _, lease := range fundResp.LockedUtxos {
		_, err := aliceLnd.RPC.WalletKit.ReleaseOutput(
			ctx, &walletrpc.ReleaseOutputRequest{
				Id: lease.Id, Outpoint: lease.Outpoint,
			},
		)
		require.NoError(t.t, err)
	}

	fundBatchResp, err := aliceTapd.FundBatch(
		ctx, &mintrpc.FundBatchRequest{
			AnchorPsbt:             fundResp.FundedPsbt,
			AssetAnchorOutputIndex: anchorIndex,
			ChangeOutputIndex:      fundResp.ChangeOutputIndex,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, mintrpc.BatchState_BATCH_STATE_PENDING,
		fundBatchResp.Batch.Batch.State)
	prepareResp, err := aliceTapd.PrepareBatch(
		ctx, &mintrpc.PrepareBatchRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, mintrpc.BatchState_BATCH_STATE_COMMITTED,
		prepareResp.Batch.State)
	preparedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(prepareResp.Batch.BatchPsbt), false,
	)
	require.NoError(t.t, err)

	// Input zero and the successor output remain byte-for-byte semantic
	// equivalents. Only the selected anchor's script is replaced.
	require.Equal(t.t, fundedPacket.UnsignedTx.TxIn[0],
		preparedPacket.UnsignedTx.TxIn[0])
	require.Equal(t.t, fundedPacket.Inputs[0], preparedPacket.Inputs[0])
	require.Equal(t.t, fundedPacket.UnsignedTx.TxOut[successorIndex],
		preparedPacket.UnsignedTx.TxOut[successorIndex])
	require.Equal(t.t, fundedPacket.Outputs[successorIndex],
		preparedPacket.Outputs[successorIndex])
	require.Equal(t.t, anchorValue,
		preparedPacket.UnsignedTx.TxOut[anchorIndex].Value)
	require.NotEqual(t.t, anchorPlaceholderScript,
		preparedPacket.UnsignedTx.TxOut[anchorIndex].PkScript)
	for idx := 2; idx < len(fundedPacket.UnsignedTx.TxOut); idx++ {
		require.Equal(t.t, fundedPacket.UnsignedTx.TxOut[idx],
			preparedPacket.UnsignedTx.TxOut[idx])
		require.Equal(t.t, fundedPacket.Outputs[idx],
			preparedPacket.Outputs[idx])
	}

	// Exchange independent nonces and partial signatures between the two
	// foreign wallets, then install their combined key-spend witness before
	// Alice signs any wallet-owned fee input.
	muSigWitness, signingEvidence := signForeignMuSig2Input(
		t.t, bobLnd.RPC, carolLnd.RPC, bobKey, carolKey,
		aggregateKey.FinalKey, preparedPacket,
	)
	var witnessBuf bytes.Buffer
	require.NoError(t.t, psbt.WriteTxWitness(
		&witnessBuf, wire.TxWitness{muSigWitness},
	))
	preparedPacket.Inputs[0].FinalScriptWitness = witnessBuf.Bytes()
	externalInput := preparedPacket.Inputs[0]
	preparedWithMuSig, err := fn.Serialize(preparedPacket)
	require.NoError(t.t, err)
	walletSignResp := aliceLnd.RPC.SignPsbt(&walletrpc.SignPsbtRequest{
		FundedPsbt: preparedWithMuSig,
	})
	require.NotContains(t.t, walletSignResp.SignedInputs, uint32(0))
	require.NotEmpty(t.t, walletSignResp.SignedInputs)
	walletSignedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(walletSignResp.SignedPsbt), false,
	)
	require.NoError(t.t, err)
	require.True(t.t, customAnchorForeignInputPreserved(
		preparedPacket.UnsignedTx.TxIn[0],
		walletSignedPacket.UnsignedTx.TxIn[0], externalInput,
		walletSignedPacket.Inputs[0],
	))
	require.NoError(t.t, psbt.MaybeFinalizeAll(walletSignedPacket))
	finalTx, err := psbt.Extract(walletSignedPacket)
	require.NoError(t.t, err)
	require.Equal(t.t, foreignOutpoint,
		finalTx.TxIn[0].PreviousOutPoint)
	require.Equal(t.t, fundedPacket.UnsignedTx.TxOut[successorIndex],
		finalTx.TxOut[successorIndex])
	assertAllInputsScriptValid(t.t, walletSignedPacket, finalTx)

	signedBytes, err := fn.Serialize(walletSignedPacket)
	require.NoError(t.t, err)
	ctxFinalize, cancelFinalize := context.WithTimeout(
		ctx, defaultWaitTimeout,
	)
	finalizeResp, err := aliceTapd.FinalizeBatch(
		ctxFinalize, &mintrpc.FinalizeBatchRequest{
			SignedPsbt: signedBytes,
		},
	)
	cancelFinalize()
	require.NoError(t.t, err)
	require.Equal(t.t, mintrpc.BatchState_BATCH_STATE_BROADCAST,
		finalizeResp.Batch.State)

	hashes, err := WaitForNTxsInMempool(miner, 1, defaultWaitTimeout)
	require.NoError(t.t, err)
	require.Len(t.t, hashes, 1)
	require.Equal(t.t, finalTx.TxHash(), *hashes[0])
	block := MineBlocks(t.t, miner, 1, 1)[0]
	ctxWait, cancelWait := context.WithTimeout(ctx, defaultWaitTimeout)
	defer cancelWait()
	WaitForBatchState(
		t.t, ctxWait, aliceTapd, defaultWaitTimeout,
		finalizeResp.Batch.BatchKey,
		mintrpc.BatchState_BATCH_STATE_FINALIZED,
	)
	mintedAssets := AssertAssetsMintedAtOutpoint(
		t.t, aliceTapd, mintReqs, wire.OutPoint{
			Hash: finalTx.TxHash(), Index: anchorIndex,
		}, block.BlockHash(),
	)
	require.Len(t.t, mintedAssets, 1)
	mintedAsset := mintedAssets[0]
	require.Equal(t.t, foreignOutpoint.String(),
		mintedAsset.AssetGenesis.GenesisPoint)
	proofBlob := AssertAssetProofs(
		t.t, aliceTapd, aliceLnd.RPC.ChainKit, mintedAsset,
	)
	proofFile := &proof.File{}
	require.NoError(t.t, proofFile.Decode(bytes.NewReader(proofBlob)))
	mintProof, err := proofFile.LastProof()
	require.NoError(t.t, err)
	require.Equal(t.t, foreignOutpoint, mintProof.PrevOut)
	require.Equal(t.t, uint32(anchorIndex),
		mintProof.InclusionProof.OutputIndex)
	require.True(t.t,
		mintProof.InclusionProof.InternalKey.IsEqual(anchorInternalKey))
	require.Equal(t.t, finalTx.TxOut[successorIndex],
		mintProof.AnchorTx.TxOut[successorIndex])

	const sendAmount = uint64(40)
	bobAddr, err := bobTapd.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: mintedAsset.AssetGenesis.AssetId,
		Amt:     sendAmount,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bobTapd, mintedAsset, bobAddr)
	sendResp, sendEvents := sendAssetsToAddr(t, aliceTapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, miner, aliceTapd, sendResp,
		mintedAsset.AssetGenesis.AssetId,
		[]uint64{mintedAsset.Amount - sendAmount, sendAmount}, 0, 1,
	)
	var postSpendTx wire.MsgTx
	require.NoError(t.t, postSpendTx.Deserialize(
		bytes.NewReader(sendResp.Transfer.AnchorTx),
	))
	successorOutpoint := wire.OutPoint{
		Hash: finalTx.TxHash(), Index: successorIndex,
	}
	for _, txIn := range postSpendTx.TxIn {
		require.NotEqual(t.t, successorOutpoint, txIn.PreviousOutPoint,
			"asset send spent the independent collateral successor")
	}
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)
	AssertBalanceByID(
		t.t, bobTapd, mintedAsset.AssetGenesis.AssetId, sendAmount,
	)
	postSpendProofResp, err := bobTapd.ExportProof(
		ctx, &taprpc.ExportProofRequest{
			AssetId:   mintedAsset.AssetGenesis.AssetId,
			ScriptKey: bobAddr.ScriptKey,
		},
	)
	require.NoError(t.t, err)
	postSpendVerify, err := bobTapd.VerifyProof(
		ctx, &taprpc.ProofFile{RawProofFile: postSpendProofResp.RawProofFile},
	)
	require.NoError(t.t, err)
	require.True(t.t, postSpendVerify.Valid)
	postSpendTxID, err := chainhash.NewHash(sendResp.Transfer.AnchorTxHash)
	require.NoError(t.t, err)

	campaignID := customAnchorEvidenceBinding(t.t,
		"TAPD_ITEST_CAMPAIGN_ID", false)
	cohortID := customAnchorEvidenceBinding(t.t,
		"TAPD_ITEST_COHORT_ID", true)
	producerDigest := customAnchorProducerBinarySHA256(t.t)
	aliceInfo := aliceLnd.RPC.GetInfo()
	identityBytes, err := hex.DecodeString(aliceInfo.IdentityPubkey)
	require.NoError(t.t, err)
	require.Len(t.t, identityBytes, btcec.PubKeyBytesLenCompressed)
	_, err = btcec.ParsePubKey(identityBytes)
	require.NoError(t.t, err)

	// Derive the exact locator again rather than treating the earlier public
	// key as proof that Alice controls it.
	anchorLocator := &signrpc.KeyLocator{
		KeyFamily: anchorKeyResp.KeyLoc.KeyFamily,
		KeyIndex:  anchorKeyResp.KeyLoc.KeyIndex,
	}
	require.Equal(t.t, int32(asset.TaprootAssetsKeyFamily),
		anchorLocator.KeyFamily)
	derivedAnchorKey := aliceLnd.RPC.DeriveKey(anchorLocator)
	require.Equal(t.t, anchorKeyResp.RawKeyBytes,
		derivedAnchorKey.RawKeyBytes)
	require.Equal(t.t, anchorKeyResp.KeyLoc, derivedAnchorKey.KeyLoc)

	chainEvidence, err := collectCustomAnchorChainEvidence(
		miner, uint32(foreignFundingHeight),
		foreignFundingBlock.BlockHash(),
	)
	require.NoError(t.t, err)
	for _, expectedTx := range []chainhash.Hash{
		*foreignTxID, finalTx.TxHash(), *postSpendTxID,
	} {
		txHeight, ok := customAnchorChainTxHeight(
			chainEvidence, expectedTx,
		)
		require.True(t.t, ok, "transaction %s absent from chain evidence",
			expectedTx)
		require.GreaterOrEqual(t.t,
			chainEvidence.TipHeight-txHeight+1, uint32(1),
		)
	}
	feeOutpoints := make([]wire.OutPoint, 0,
		len(fundedPacket.UnsignedTx.TxIn)-1)
	for idx := 1; idx < len(fundedPacket.UnsignedTx.TxIn); idx++ {
		feeOutpoints = append(feeOutpoints,
			fundedPacket.UnsignedTx.TxIn[idx].PreviousOutPoint)
	}
	commitment, err := customAnchorAuthorityCommitment(
		campaignID, cohortID, producerDigest, identityBytes,
		walletEvidence, foreignOutpoint, feeOutpoints,
		anchorLocator, schnorr.SerializePubKey(anchorInternalKey),
		chainEvidence,
	)
	require.NoError(t.t, err)
	popResp := aliceLnd.RPC.SignMessageSigner(&signrpc.SignMessageReq{
		Msg: commitment[:], KeyLoc: anchorLocator, SchnorrSig: true,
		Tag: []byte(customAnchorAuthorityTag),
	})
	require.Len(t.t, popResp.Signature, schnorr.SignatureSize)
	popSig, err := schnorr.ParseSignature(popResp.Signature)
	require.NoError(t.t, err)
	popDigest := chainhash.TaggedHash(
		[]byte(customAnchorAuthorityTag), commitment[:],
	)
	require.True(t.t, popSig.Verify(
		popDigest[:], anchorInternalKey,
	))
	authorityEvidence := customAnchorAuthorityEvidence{
		AliceIdentityPubKey: aliceInfo.IdentityPubkey,
		WalletUTXO:          walletEvidence,
		AnchorKeyPoP: customAnchorAuthorityPoPEvidence{
			Algorithm: "BIP340 over TaggedHash(tag, commitment)",
			Tag:       customAnchorAuthorityTag,
			CommitmentEncoding: "SHA256(M10-ISSUE721-AUTHORITY-" +
				"COMMITMENT-V1\\0 || lenpref(campaign) || " +
				"lenpref(cohort) || lenpref(producer_sha256_hex) || " +
				"alice_identity_compressed[33] || query_i32be_i32be_" +
				"lenpref(account)_bool || wallet_root[32] || " +
				"wallet_count_u64be || foreign_outpoint[36] || " +
				"fee_count_u32be || sorted_fee_outpoints[36]* || " +
				"locator_family_i32be || locator_index_i32be || " +
				"anchor_xonly[32] || tip_hash_display_bytes_be[32] || " +
				"tip_height_u32be)",
			Locator: customAnchorKeyLocatorEvidence{
				Family: anchorLocator.KeyFamily,
				Index:  anchorLocator.KeyIndex,
			},
			PublicKey: hex.EncodeToString(
				schnorr.SerializePubKey(anchorInternalKey),
			),
			Commitment: hex.EncodeToString(commitment[:]),
			Signature:  hex.EncodeToString(popResp.Signature),
		},
		Chain: chainEvidence,
	}
	var (
		finalTxBuf        bytes.Buffer
		foreignFundingBuf bytes.Buffer
		foreignBlockBuf   bytes.Buffer
	)
	require.NoError(t.t, finalTx.Serialize(&finalTxBuf))
	require.NoError(t.t, foreignFundingTx.Serialize(&foreignFundingBuf))
	require.NoError(t.t, foreignFundingBlock.Serialize(&foreignBlockBuf))

	writeCustomAnchorMuSig2Evidence(t.t, customAnchorMuSig2Evidence{
		Schema:               "taproot_assets_custom_anchor_musig2_evidence_v2",
		CampaignID:           campaignID,
		CohortID:             cohortID,
		ProducerBinarySHA256: producerDigest,
		Version:              2,
		ForeignFundingTx: hex.EncodeToString(
			foreignFundingBuf.Bytes(),
		),
		ForeignFundingBlock: hex.EncodeToString(
			foreignBlockBuf.Bytes(),
		),
		ForeignFundingBlockHash: foreignFundingBlock.BlockHash().String(),
		ForeignFundingTxIndex:   uint32(foreignFundingTxIndex),
		ForeignGenesisOutpoint:  foreignOutpoint.String(),
		ForeignPrevoutValue:     foreignPrevOut.Value,
		ForeignPrevoutScript: hex.EncodeToString(
			foreignPrevOut.PkScript,
		),
		SuccessorOutputIndex:   successorIndex,
		SuccessorValue:         successorValue,
		SuccessorScript:        hex.EncodeToString(foreignScript),
		AssetAnchorOutputIndex: anchorIndex,
		AssetAnchorValue:       anchorValue,
		AssetAnchorInternalKey: hex.EncodeToString(
			schnorr.SerializePubKey(anchorInternalKey),
		),
		AssetAnchorKeyFamily: anchorKeyResp.KeyLoc.KeyFamily,
		AssetAnchorKeyIndex:  anchorKeyResp.KeyLoc.KeyIndex,
		FundBatchAnchorPSBT:  hex.EncodeToString(fundResp.FundedPsbt),
		FundBatchAnchorIndex: anchorIndex,
		FundBatchChangeIndex: fundResp.ChangeOutputIndex,
		ChangeOutputIndex:    fundResp.ChangeOutputIndex,
		TemplatePSBT:         hex.EncodeToString(templateBytes),
		FundedPSBT:           hex.EncodeToString(fundResp.FundedPsbt),
		PreparedPSBT: hex.EncodeToString(
			prepareResp.Batch.BatchPsbt,
		),
		ExternalFinalizedPSBT: hex.EncodeToString(preparedWithMuSig),
		WalletSignedPSBT: hex.EncodeToString(
			walletSignResp.SignedPsbt,
		),
		WalletSignedInputIndexes: walletSignResp.SignedInputs,
		FinalizedPSBT:            hex.EncodeToString(signedBytes),
		FinalTransaction:         hex.EncodeToString(finalTxBuf.Bytes()),
		MintTransactionID:        finalTx.TxHash().String(),
		MintBlockHash:            block.BlockHash().String(),
		MintAssetID: hex.EncodeToString(
			mintedAsset.AssetGenesis.AssetId,
		),
		MintProof:              hex.EncodeToString(proofBlob),
		PostSpendTransactionID: postSpendTxID.String(),
		PostSpendTransaction:   hex.EncodeToString(sendResp.Transfer.AnchorTx),
		PostSpendProof: hex.EncodeToString(
			postSpendProofResp.RawProofFile,
		),
		MuSig2Signing: signingEvidence,
		Authority:     authorityEvidence,
	})
}

func customAnchorForeignInputPreserved(expectedTxIn, actualTxIn *wire.TxIn,
	expectedInput, actualInput psbt.PInput) bool {

	if !reflect.DeepEqual(expectedTxIn, actualTxIn) {
		return false
	}

	hintsAbsent := actualInput.TaprootInternalKey == nil &&
		actualInput.TaprootBip32Derivation == nil
	hintsEqual := bytes.Equal(
		expectedInput.TaprootInternalKey,
		actualInput.TaprootInternalKey,
	) && reflect.DeepEqual(
		expectedInput.TaprootBip32Derivation,
		actualInput.TaprootBip32Derivation,
	)
	if !hintsAbsent && !hintsEqual {
		return false
	}

	expectedInput.TaprootInternalKey = nil
	expectedInput.TaprootBip32Derivation = nil
	actualInput.TaprootInternalKey = nil
	actualInput.TaprootBip32Derivation = nil

	return reflect.DeepEqual(expectedInput, actualInput)
}

func TestCustomAnchorForeignInputPreserved(t *testing.T) {
	txIn := &wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 7}}
	expected := psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value: 10_000, PkScript: []byte{txscript.OP_TRUE},
		},
		SighashType:        txscript.SigHashDefault,
		FinalScriptWitness: []byte{1, 2, 3},
		TaprootInternalKey: bytes.Repeat([]byte{2}, 32),
		TaprootMerkleRoot:  bytes.Repeat([]byte{3}, 32),
		TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey: bytes.Repeat([]byte{2}, 32),
		}},
		Unknowns: []*psbt.Unknown{{
			Key: []byte{0x50}, Value: []byte("foreign"),
		}},
	}

	require.True(t, customAnchorForeignInputPreserved(
		txIn, txIn, expected, expected,
	))
	pruned := expected
	pruned.TaprootInternalKey = nil
	pruned.TaprootBip32Derivation = nil
	require.True(t, customAnchorForeignInputPreserved(
		txIn, txIn, expected, pruned,
	))

	testCases := []struct {
		name   string
		mutate func(*wire.TxIn, *psbt.PInput)
	}{
		{
			name: "outpoint",
			mutate: func(txIn *wire.TxIn, _ *psbt.PInput) {
				txIn.PreviousOutPoint.Index++
			},
		},
		{
			name: "witness",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.FinalScriptWitness = []byte{4, 5, 6}
			},
		},
		{
			name: "witness utxo value",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.WitnessUtxo = &wire.TxOut{
					Value:    9_999,
					PkScript: input.WitnessUtxo.PkScript,
				}
			},
		},
		{
			name: "witness utxo script",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.WitnessUtxo = &wire.TxOut{
					Value: input.WitnessUtxo.Value,
					PkScript: []byte{
						txscript.OP_FALSE,
					},
				}
			},
		},
		{
			name: "unknown metadata",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.Unknowns = []*psbt.Unknown{{
					Key: []byte{0x50}, Value: []byte("changed"),
				}}
			},
		},
		{
			name: "sighash",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.SighashType = txscript.SigHashAll
			},
		},
		{
			name: "script signature",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.FinalScriptSig = []byte{txscript.OP_TRUE}
			},
		},
		{
			name: "taproot signature",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.TaprootKeySpendSig = []byte{1}
			},
		},
		{
			name: "taproot leaf script",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.TaprootLeafScript =
					[]*psbt.TaprootTapLeafScript{{
						ControlBlock: []byte{1},
						Script:       []byte{txscript.OP_TRUE},
					}}
			},
		},
		{
			name: "merkle root",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.TaprootMerkleRoot = bytes.Repeat([]byte{4}, 32)
			},
		},
		{
			name: "internal key hint",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.TaprootInternalKey = bytes.Repeat([]byte{5}, 32)
			},
		},
		{
			name: "derivation hint",
			mutate: func(_ *wire.TxIn, input *psbt.PInput) {
				input.TaprootBip32Derivation =
					[]*psbt.TaprootBip32Derivation{{
						XOnlyPubKey: bytes.Repeat([]byte{6}, 32),
					}}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actualTxIn := *txIn
			actualInput := pruned
			testCase.mutate(&actualTxIn, &actualInput)
			require.False(t, customAnchorForeignInputPreserved(
				txIn, &actualTxIn, expected, actualInput,
			))
		})
	}
}

func TestCustomAnchorSparseWalletCommitment(t *testing.T) {
	hashA := chainhash.Hash{1}
	hashB := chainhash.Hash{2}
	utxos := []*lnrpc.Utxo{
		{
			AmountSat: 40_000, PkScript: "5120" +
				"1111111111111111111111111111111111111111111111111111111111111111",
			Outpoint: &lnrpc.OutPoint{
				TxidStr: hashA.String(), OutputIndex: 3,
			},
		},
		{
			AmountSat: 90_000, PkScript: "0014" +
				"2222222222222222222222222222222222222222",
			Outpoint: &lnrpc.OutPoint{
				TxidStr: hashB.String(), OutputIndex: 7,
			},
		},
	}
	tree, err := newCustomAnchorSparseTree(utxos)
	require.NoError(t, err)
	root := tree.root()

	// Inventory ordering is irrelevant, while every disclosed field is bound.
	reversed, err := newCustomAnchorSparseTree([]*lnrpc.Utxo{
		utxos[1], utxos[0],
	})
	require.NoError(t, err)
	require.Equal(t, root, reversed.root())

	membership, err := tree.proof(wire.OutPoint{
		Hash: hashA, Index: 3,
	}, true)
	require.NoError(t, err)
	require.NoError(t, verifyCustomAnchorSparseProof(
		membership, root, true,
	))

	foreignHash := chainhash.Hash{9}
	nonMembership, err := tree.proof(wire.OutPoint{
		Hash: foreignHash, Index: 1,
	}, false)
	require.NoError(t, err)
	require.NoError(t, verifyCustomAnchorSparseProof(
		nonMembership, root, false,
	))

	mutatedSibling := membership
	mutatedSibling.Siblings = append([]string(nil), membership.Siblings...)
	mutatedSibling.Siblings[0] = hex.EncodeToString(make([]byte, 32))
	require.Error(t, verifyCustomAnchorSparseProof(
		mutatedSibling, root, true,
	))
	mutatedLeaf := membership
	leafCopy := *membership.Leaf
	leafCopy.Value++
	mutatedLeaf.Leaf = &leafCopy
	require.Error(t, verifyCustomAnchorSparseProof(
		mutatedLeaf, root, true,
	))
	mutatedKey := membership
	mutatedKey.Key = hex.EncodeToString(make([]byte, 32))
	require.Error(t, verifyCustomAnchorSparseProof(
		mutatedKey, root, true,
	))

	_, err = newCustomAnchorSparseTree([]*lnrpc.Utxo{
		utxos[0], utxos[0],
	})
	require.ErrorContains(t, err, "duplicate UTXO")
}

func TestCustomAnchorAuthorityCommitmentBindsFields(t *testing.T) {
	identity := append([]byte{2}, bytes.Repeat([]byte{3}, 32)...)
	anchorKey := bytes.Repeat([]byte{4}, 32)
	foreign := wire.OutPoint{Hash: chainhash.Hash{5}, Index: 6}
	fees := []wire.OutPoint{
		{Hash: chainhash.Hash{7}, Index: 8},
		{Hash: chainhash.Hash{9}, Index: 10},
	}
	locator := &signrpc.KeyLocator{KeyFamily: 212, KeyIndex: 11}
	wallet := customAnchorWalletCommitmentEvidence{
		Query: customAnchorWalletQueryEvidence{
			MinConfirmations: 0, MaxConfirmations: math.MaxInt32,
			Account: "", UnconfirmedOnly: false,
		},
		Root:  hex.EncodeToString(bytes.Repeat([]byte{12}, 32)),
		Count: 13,
	}
	chain := customAnchorChainEvidence{
		TipHash: chainhash.Hash{14}.String(), TipHeight: 15,
	}
	commit := func(campaign, cohort, producer string, id []byte,
		walletValue customAnchorWalletCommitmentEvidence,
		foreignValue wire.OutPoint, feeValues []wire.OutPoint,
		locatorValue *signrpc.KeyLocator, key []byte,
		chainValue customAnchorChainEvidence) [32]byte {

		result, err := customAnchorAuthorityCommitment(
			campaign, cohort, producer, id, walletValue,
			foreignValue, feeValues, locatorValue, key, chainValue,
		)
		require.NoError(t, err)
		return result
	}
	baseline := commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, fees, locator, anchorKey, chain,
	)
	reversedFees := []wire.OutPoint{fees[1], fees[0]}
	require.Equal(t, baseline, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, reversedFees, locator, anchorKey, chain,
	))

	mutations := make([][32]byte, 0, 13)
	mutations = append(mutations, commit(
		"10112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, fees, locator, anchorKey, chain,
	))
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("3", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, fees, locator, anchorKey, chain,
	))
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("3", 64), identity,
		wallet, foreign, fees, locator, anchorKey, chain,
	))
	mutatedIdentity := append([]byte(nil), identity...)
	mutatedIdentity[1] ^= 1
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64),
		mutatedIdentity, wallet, foreign, fees, locator, anchorKey, chain,
	))
	mutatedWallet := wallet
	mutatedWallet.Query.MaxConfirmations--
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		mutatedWallet, foreign, fees, locator, anchorKey, chain,
	))
	mutatedWallet = wallet
	mutatedWallet.Count++
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		mutatedWallet, foreign, fees, locator, anchorKey, chain,
	))
	mutatedWallet = wallet
	mutatedWallet.Root = hex.EncodeToString(bytes.Repeat([]byte{13}, 32))
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		mutatedWallet, foreign, fees, locator, anchorKey, chain,
	))
	mutatedForeign := foreign
	mutatedForeign.Index++
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, mutatedForeign, fees, locator, anchorKey, chain,
	))
	mutatedFees := append([]wire.OutPoint(nil), fees...)
	mutatedFees[0].Index++
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, mutatedFees, locator, anchorKey, chain,
	))
	mutatedLocator := &signrpc.KeyLocator{
		KeyFamily: locator.KeyFamily,
		KeyIndex:  locator.KeyIndex,
	}
	mutatedLocator.KeyIndex++
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, fees, mutatedLocator, anchorKey, chain,
	))
	mutatedAnchor := append([]byte(nil), anchorKey...)
	mutatedAnchor[0] ^= 1
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, fees, locator, mutatedAnchor, chain,
	))
	mutatedChain := chain
	mutatedChain.TipHeight++
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, fees, locator, anchorKey, mutatedChain,
	))
	mutatedChain = chain
	mutatedChain.TipHash = chainhash.Hash{15}.String()
	mutations = append(mutations, commit(
		"00112233445566778899aabbccddeeff",
		strings.Repeat("1", 64), strings.Repeat("2", 64), identity,
		wallet, foreign, fees, locator, anchorKey, mutatedChain,
	))
	for index, mutation := range mutations {
		require.NotEqual(t, baseline, mutation, "mutation %d", index)
	}
}

func TestCustomAnchorRegtestBits(t *testing.T) {
	block := &wire.MsgBlock{Header: wire.BlockHeader{
		Bits: chaincfg.RegressionNetParams.PowLimitBits,
	}}
	require.NoError(t, validateCustomAnchorRegtestBits(block))

	block.Header.Bits--
	require.ErrorContains(t, validateCustomAnchorRegtestBits(block),
		"unexpected regtest bits")
	require.ErrorContains(t, validateCustomAnchorRegtestBits(nil),
		"nil block")
}

func TestAssetAnchorOutpointCheck(t *testing.T) {
	anchorHash := chainhash.Hash{1}
	blockHash := chainhash.Hash{2}
	anchorOutpoint := wire.OutPoint{Hash: anchorHash, Index: 1}
	rpcAsset := &taprpc.Asset{ChainAnchor: &taprpc.AnchorInfo{
		AnchorOutpoint:  anchorOutpoint.String(),
		AnchorBlockHash: blockHash.String(),
	}}

	require.NoError(t, AssetAnchorOutpointCheck(
		anchorOutpoint, blockHash,
	)(rpcAsset))
	require.Error(t, AssetAnchorOutpointCheck(
		wire.OutPoint{Hash: anchorHash, Index: 0}, blockHash,
	)(rpcAsset))
}

func customAnchorEvidenceBinding(t *testing.T, name string,
	requireSHA256 bool) string {

	value := os.Getenv(name)
	if os.Getenv("TAPD_ITEST_EVIDENCE_DIR") == "" {
		return value
	}
	require.NotEmpty(t, value, "%s is required in evidence mode", name)
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err, "%s must be lowercase hex", name)
	require.Equal(t, value, hex.EncodeToString(decoded),
		"%s must be canonical lowercase hex", name)
	if requireSHA256 {
		require.Len(t, decoded, sha256.Size, "%s must be SHA256", name)
	} else {
		require.Len(t, decoded, 16,
			"%s must decode to exactly 16 bytes", name)
	}

	return value
}

func customAnchorOutpointEvidenceFromWire(
	outpoint wire.OutPoint) customAnchorOutpointEvidence {

	return customAnchorOutpointEvidence{
		TxID: outpoint.Hash.String(), OutputIndex: outpoint.Index,
	}
}

func customAnchorOutpointBytes(
	outpoint customAnchorOutpointEvidence) ([]byte, error) {

	txid, err := hex.DecodeString(outpoint.TxID)
	if err != nil {
		return nil, fmt.Errorf("decode display txid: %w", err)
	}
	if len(txid) != chainhash.HashSize {
		return nil, fmt.Errorf("display txid must be 32 bytes")
	}
	result := make([]byte, chainhash.HashSize+4)
	copy(result, txid)
	binary.BigEndian.PutUint32(result[chainhash.HashSize:],
		outpoint.OutputIndex)

	return result, nil
}

func customAnchorWalletLeaf(utxo *lnrpc.Utxo) (
	customAnchorWalletLeafEvidence, error) {

	if utxo == nil || utxo.Outpoint == nil {
		return customAnchorWalletLeafEvidence{}, fmt.Errorf("nil UTXO")
	}
	if utxo.AmountSat < 0 {
		return customAnchorWalletLeafEvidence{}, fmt.Errorf(
			"negative UTXO amount")
	}
	txid, err := chainhash.NewHashFromStr(utxo.Outpoint.TxidStr)
	if err != nil {
		return customAnchorWalletLeafEvidence{}, fmt.Errorf(
			"invalid UTXO txid: %w", err)
	}
	script, err := hex.DecodeString(utxo.PkScript)
	if err != nil {
		return customAnchorWalletLeafEvidence{}, fmt.Errorf(
			"invalid UTXO script: %w", err)
	}

	return customAnchorWalletLeafEvidence{
		Outpoint: customAnchorOutpointEvidence{
			TxID: txid.String(), OutputIndex: utxo.Outpoint.OutputIndex,
		},
		Value:  uint64(utxo.AmountSat),
		Script: hex.EncodeToString(script),
	}, nil
}

func customAnchorSparseKey(outpoint customAnchorOutpointEvidence) (
	[32]byte, error) {

	outpointBytes, err := customAnchorOutpointBytes(outpoint)
	if err != nil {
		return [32]byte{}, err
	}
	preimage := append([]byte(customAnchorUTXOKeyDomain), outpointBytes...)

	return sha256.Sum256(preimage), nil
}

func customAnchorSparseLeafHash(key [32]byte,
	leaf customAnchorWalletLeafEvidence) ([32]byte, error) {

	script, err := hex.DecodeString(leaf.Script)
	if err != nil {
		return [32]byte{}, fmt.Errorf("decode script: %w", err)
	}
	if len(script) > math.MaxUint32 {
		return [32]byte{}, fmt.Errorf("script too large")
	}
	preimage := bytes.NewBufferString(customAnchorUTXOLeafDomain)
	_, _ = preimage.Write(key[:])
	requireWriteUint64(preimage, leaf.Value)
	requireWriteUint32(preimage, uint32(len(script)))
	_, _ = preimage.Write(script)

	return sha256.Sum256(preimage.Bytes()), nil
}

func customAnchorSparseNode(left, right [32]byte) [32]byte {
	preimage := make([]byte, 0, len(customAnchorUTXONodeDomain)+64)
	preimage = append(preimage, customAnchorUTXONodeDomain...)
	preimage = append(preimage, left[:]...)
	preimage = append(preimage, right[:]...)

	return sha256.Sum256(preimage)
}

func customAnchorPrefix(key [32]byte, bitCount int) [32]byte {
	if bitCount == 256 {
		return key
	}
	result := key
	byteIndex := bitCount / 8
	remaining := bitCount % 8
	if remaining == 0 {
		for idx := byteIndex; idx < len(result); idx++ {
			result[idx] = 0
		}
		return result
	}
	result[byteIndex] &= byte(0xff << (8 - remaining))
	for idx := byteIndex + 1; idx < len(result); idx++ {
		result[idx] = 0
	}

	return result
}

func customAnchorSetBit(key [32]byte, bitIndex int, value bool) [32]byte {
	mask := byte(1 << (7 - bitIndex%8))
	if value {
		key[bitIndex/8] |= mask
	} else {
		key[bitIndex/8] &^= mask
	}

	return key
}

func newCustomAnchorSparseTree(utxos []*lnrpc.Utxo) (
	*customAnchorSparseTree, error) {

	tree := &customAnchorSparseTree{
		leaves: make(map[[32]byte]customAnchorWalletLeafEvidence),
	}
	tree.defaults[256] = sha256.Sum256(
		[]byte(customAnchorUTXOEmptyDomain),
	)
	for depth := 255; depth >= 0; depth-- {
		tree.defaults[depth] = customAnchorSparseNode(
			tree.defaults[depth+1], tree.defaults[depth+1],
		)
	}
	tree.levels[256] = make(map[[32]byte][32]byte)
	outpoints := make(map[string]struct{}, len(utxos))
	for _, utxo := range utxos {
		leaf, err := customAnchorWalletLeaf(utxo)
		if err != nil {
			return nil, err
		}
		outpointID := fmt.Sprintf("%s:%d", leaf.Outpoint.TxID,
			leaf.Outpoint.OutputIndex)
		if _, ok := outpoints[outpointID]; ok {
			return nil, fmt.Errorf("duplicate UTXO %s", outpointID)
		}
		outpoints[outpointID] = struct{}{}
		key, err := customAnchorSparseKey(leaf.Outpoint)
		if err != nil {
			return nil, err
		}
		if _, ok := tree.leaves[key]; ok {
			return nil, fmt.Errorf("sparse key collision for %s", outpointID)
		}
		leafHash, err := customAnchorSparseLeafHash(key, leaf)
		if err != nil {
			return nil, err
		}
		tree.leaves[key] = leaf
		tree.levels[256][key] = leafHash
	}
	for depth := 255; depth >= 0; depth-- {
		parents := make(map[[32]byte]struct{})
		for child := range tree.levels[depth+1] {
			parents[customAnchorPrefix(child, depth)] = struct{}{}
		}
		tree.levels[depth] = make(map[[32]byte][32]byte, len(parents))
		for parent := range parents {
			leftKey := customAnchorSetBit(parent, depth, false)
			rightKey := customAnchorSetBit(parent, depth, true)
			left, ok := tree.levels[depth+1][leftKey]
			if !ok {
				left = tree.defaults[depth+1]
			}
			right, ok := tree.levels[depth+1][rightKey]
			if !ok {
				right = tree.defaults[depth+1]
			}
			tree.levels[depth][parent] = customAnchorSparseNode(
				left, right,
			)
		}
	}

	return tree, nil
}

func (t *customAnchorSparseTree) root() [32]byte {
	root, ok := t.levels[0][[32]byte{}]
	if !ok {
		return t.defaults[0]
	}

	return root
}

func (t *customAnchorSparseTree) proof(outpoint wire.OutPoint,
	present bool) (customAnchorSparseProofEvidence, error) {

	key, err := customAnchorSparseKey(
		customAnchorOutpointEvidenceFromWire(outpoint),
	)
	if err != nil {
		return customAnchorSparseProofEvidence{}, err
	}
	leaf, exists := t.leaves[key]
	if exists != present {
		return customAnchorSparseProofEvidence{}, fmt.Errorf(
			"outpoint %s presence=%v, expected=%v", outpoint, exists,
			present)
	}
	siblings := make([]string, 0, 256)
	for proofIndex := 0; proofIndex < 256; proofIndex++ {
		depth := 255 - proofIndex
		siblingKey := customAnchorPrefix(key, depth+1)
		bitSet := key[depth/8]&(1<<(7-depth%8)) != 0
		siblingKey = customAnchorSetBit(siblingKey, depth, !bitSet)
		sibling, ok := t.levels[depth+1][siblingKey]
		if !ok {
			sibling = t.defaults[depth+1]
		}
		siblings = append(siblings, hex.EncodeToString(sibling[:]))
	}
	proof := customAnchorSparseProofEvidence{
		Key: hex.EncodeToString(key[:]), Siblings: siblings,
	}
	if present {
		leafCopy := leaf
		proof.Leaf = &leafCopy
	}

	return proof, nil
}

func verifyCustomAnchorSparseProof(proof customAnchorSparseProofEvidence,
	root [32]byte, present bool) error {

	keyBytes, err := hex.DecodeString(proof.Key)
	if err != nil || len(keyBytes) != sha256.Size {
		return fmt.Errorf("invalid proof key")
	}
	var key [32]byte
	copy(key[:], keyBytes)
	if len(proof.Siblings) != 256 {
		return fmt.Errorf("proof must have 256 siblings")
	}
	var current [32]byte
	if present {
		if proof.Leaf == nil {
			return fmt.Errorf("membership proof missing leaf")
		}
		expectedKey, err := customAnchorSparseKey(proof.Leaf.Outpoint)
		if err != nil || expectedKey != key {
			return fmt.Errorf("leaf key mismatch")
		}
		current, err = customAnchorSparseLeafHash(key, *proof.Leaf)
		if err != nil {
			return err
		}
	} else {
		if proof.Leaf != nil {
			return fmt.Errorf("non-membership proof contains leaf")
		}
		current = sha256.Sum256([]byte(customAnchorUTXOEmptyDomain))
	}
	for proofIndex, siblingHex := range proof.Siblings {
		siblingBytes, err := hex.DecodeString(siblingHex)
		if err != nil || len(siblingBytes) != sha256.Size {
			return fmt.Errorf("invalid sibling %d", proofIndex)
		}
		var sibling [32]byte
		copy(sibling[:], siblingBytes)
		bitIndex := 255 - proofIndex
		bitSet := key[bitIndex/8]&(1<<(7-bitIndex%8)) != 0
		if bitSet {
			current = customAnchorSparseNode(sibling, current)
		} else {
			current = customAnchorSparseNode(current, sibling)
		}
	}
	if current != root {
		return fmt.Errorf("root mismatch")
	}

	return nil
}

type customAnchorChainSource interface {
	GetBestBlock() (*chainhash.Hash, int32)
	GetBlock(*chainhash.Hash) *wire.MsgBlock
}

func collectCustomAnchorChainEvidence(source customAnchorChainSource,
	startHeight uint32, startHash chainhash.Hash) (
	customAnchorChainEvidence, error) {

	tipHash, tipHeightSigned := source.GetBestBlock()
	if tipHeightSigned < 0 || uint32(tipHeightSigned) < startHeight {
		return customAnchorChainEvidence{}, fmt.Errorf("invalid chain height")
	}
	tipHeight := uint32(tipHeightSigned)
	blocks := make([]customAnchorChainBlockEvidence, 0,
		tipHeight-startHeight+1)
	currentHash := *tipHash
	for height := tipHeight; ; height-- {
		block := source.GetBlock(&currentHash)
		if block.BlockHash() != currentHash {
			return customAnchorChainEvidence{}, fmt.Errorf(
				"block hash mismatch at height %d", height)
		}
		if err := validateCustomAnchorRegtestBits(block); err != nil {
			return customAnchorChainEvidence{}, fmt.Errorf(
				"block %d: %w", height, err)
		}
		var raw bytes.Buffer
		if err := block.Serialize(&raw); err != nil {
			return customAnchorChainEvidence{}, err
		}
		blocks = append(blocks, customAnchorChainBlockEvidence{
			Height: height, Hash: currentHash.String(),
			RawBlock: hex.EncodeToString(raw.Bytes()),
		})
		if height == startHeight {
			if currentHash != startHash {
				return customAnchorChainEvidence{}, fmt.Errorf(
					"chain does not reach funding block")
			}
			break
		}
		currentHash = block.Header.PrevBlock
	}
	for left, right := 0, len(blocks)-1; left < right; {
		blocks[left], blocks[right] = blocks[right], blocks[left]
		left++
		right--
	}

	return customAnchorChainEvidence{
		Network: "regtest", StartHeight: startHeight,
		TipHeight: tipHeight, TipHash: tipHash.String(), Blocks: blocks,
	}, nil
}

func validateCustomAnchorRegtestBits(block *wire.MsgBlock) error {
	if block == nil {
		return fmt.Errorf("nil block")
	}
	expected := chaincfg.RegressionNetParams.PowLimitBits
	if block.Header.Bits != expected {
		return fmt.Errorf("unexpected regtest bits %08x, want %08x",
			block.Header.Bits, expected)
	}

	return nil
}

func customAnchorChainTxHeight(chain customAnchorChainEvidence,
	txID chainhash.Hash) (uint32, bool) {

	for _, blockEvidence := range chain.Blocks {
		raw, err := hex.DecodeString(blockEvidence.RawBlock)
		if err != nil {
			return 0, false
		}
		var block wire.MsgBlock
		if err := block.Deserialize(bytes.NewReader(raw)); err != nil {
			return 0, false
		}
		for _, tx := range block.Transactions {
			if tx.TxHash() == txID {
				return blockEvidence.Height, true
			}
		}
	}

	return 0, false
}

func customAnchorAuthorityCommitment(campaignID, cohortID,
	producerDigest string, identity []byte,
	wallet customAnchorWalletCommitmentEvidence,
	foreign wire.OutPoint, feeOutpoints []wire.OutPoint,
	locator *signrpc.KeyLocator, anchorXOnly []byte,
	chain customAnchorChainEvidence) ([32]byte, error) {

	if len(identity) != btcec.PubKeyBytesLenCompressed {
		return [32]byte{}, fmt.Errorf("invalid identity length")
	}
	if len(anchorXOnly) != schnorr.PubKeyBytesLen {
		return [32]byte{}, fmt.Errorf("invalid anchor key length")
	}
	root, err := hex.DecodeString(wallet.Root)
	if err != nil || len(root) != sha256.Size {
		return [32]byte{}, fmt.Errorf("invalid wallet root")
	}
	tipHash, err := hex.DecodeString(chain.TipHash)
	if err != nil || len(tipHash) != chainhash.HashSize {
		return [32]byte{}, fmt.Errorf("invalid tip hash")
	}
	foreignBytes, err := customAnchorOutpointBytes(
		customAnchorOutpointEvidenceFromWire(foreign),
	)
	if err != nil {
		return [32]byte{}, err
	}
	feeBytes := make([][]byte, 0, len(feeOutpoints))
	seenFees := make(map[string]struct{}, len(feeOutpoints))
	for _, outpoint := range feeOutpoints {
		encoded, err := customAnchorOutpointBytes(
			customAnchorOutpointEvidenceFromWire(outpoint),
		)
		if err != nil {
			return [32]byte{}, err
		}
		id := string(encoded)
		if _, ok := seenFees[id]; ok {
			return [32]byte{}, fmt.Errorf("duplicate fee outpoint")
		}
		seenFees[id] = struct{}{}
		feeBytes = append(feeBytes, encoded)
	}
	sort.Slice(feeBytes, func(i, j int) bool {
		return bytes.Compare(feeBytes[i], feeBytes[j]) < 0
	})

	preimage := bytes.NewBufferString(customAnchorAuthorityCommitmentDomain)
	for _, value := range []string{campaignID, cohortID, producerDigest} {
		if err := writeCustomAnchorLenPrefixed(preimage, []byte(value)); err != nil {

			return [32]byte{}, err
		}
	}
	_, _ = preimage.Write(identity)
	requireWriteUint32(preimage, uint32(wallet.Query.MinConfirmations))
	requireWriteUint32(preimage, uint32(wallet.Query.MaxConfirmations))
	if err := writeCustomAnchorLenPrefixed(
		preimage, []byte(wallet.Query.Account),
	); err != nil {
		return [32]byte{}, err
	}
	if wallet.Query.UnconfirmedOnly {
		_ = preimage.WriteByte(1)
	} else {
		_ = preimage.WriteByte(0)
	}
	_, _ = preimage.Write(root)
	requireWriteUint64(preimage, wallet.Count)
	_, _ = preimage.Write(foreignBytes)
	if len(feeBytes) > math.MaxUint32 {
		return [32]byte{}, fmt.Errorf("too many fee outpoints")
	}
	requireWriteUint32(preimage, uint32(len(feeBytes)))
	for _, encoded := range feeBytes {
		_, _ = preimage.Write(encoded)
	}
	requireWriteUint32(preimage, uint32(locator.KeyFamily))
	requireWriteUint32(preimage, uint32(locator.KeyIndex))
	_, _ = preimage.Write(anchorXOnly)
	_, _ = preimage.Write(tipHash)
	requireWriteUint32(preimage, chain.TipHeight)

	return sha256.Sum256(preimage.Bytes()), nil
}

func writeCustomAnchorLenPrefixed(buffer *bytes.Buffer, value []byte) error {
	if len(value) > math.MaxUint32 {
		return fmt.Errorf("value too large")
	}
	requireWriteUint32(buffer, uint32(len(value)))
	_, _ = buffer.Write(value)

	return nil
}

func requireWriteUint32(buffer *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = buffer.Write(encoded[:])
}

func requireWriteUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = buffer.Write(encoded[:])
}

func customAnchorProducerBinarySHA256(t *testing.T) string {
	digest := os.Getenv("TAPD_ITEST_PRODUCER_SHA256")
	if os.Getenv("TAPD_ITEST_EVIDENCE_DIR") == "" {
		return digest
	}

	require.Regexp(t, "^[0-9a-f]{64}$", digest,
		"TAPD_ITEST_PRODUCER_SHA256 must be lowercase SHA256 hex")

	return digest
}

func writeCustomAnchorMuSig2Evidence(t *testing.T,
	evidence customAnchorMuSig2Evidence) {

	evidenceDir := os.Getenv("TAPD_ITEST_EVIDENCE_DIR")
	if evidenceDir == "" {
		return
	}
	require.NoError(t, os.MkdirAll(evidenceDir, 0o700))
	evidenceBytes, err := json.MarshalIndent(evidence, "", "  ")
	require.NoError(t, err)
	evidenceBytes = append(evidenceBytes, '\n')
	evidencePath := filepath.Join(
		evidenceDir, "custom_anchor_foreign_musig2.json",
	)
	require.NoError(t, os.WriteFile(evidencePath, evidenceBytes, 0o600))
	t.Logf("Wrote custom anchor MuSig2 evidence: %s", evidencePath)
}

func deriveMuSig2Key(t *testing.T,
	lnd *rpc.HarnessRPC) keychain.KeyDescriptor {

	keyResp := lnd.DeriveNextKey(&walletrpc.KeyReq{
		KeyFamily: int32(asset.TaprootAssetsKeyFamily),
	})
	pubKey, err := btcec.ParsePubKey(keyResp.RawKeyBytes)
	require.NoError(t, err)

	return keychain.KeyDescriptor{
		PubKey: pubKey,
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(keyResp.KeyLoc.KeyFamily),
			Index:  uint32(keyResp.KeyLoc.KeyIndex),
		},
	}
}

func signForeignMuSig2Input(t *testing.T, signerA, signerB *rpc.HarnessRPC,
	keyA, keyB keychain.KeyDescriptor, finalKey *btcec.PublicKey,
	pkt *psbt.Packet) ([]byte, customAnchorMuSig2SigningEvidence) {

	noncesA, err := musig2.GenNonces(musig2.WithPublicKey(keyA.PubKey))
	require.NoError(t, err)
	noncesB, err := musig2.GenNonces(musig2.WithPublicKey(keyB.PubKey))
	require.NoError(t, err)
	sessionA := tapMuSig2Session(
		t, signerA, keyA, keyB.PubKey.SerializeCompressed(), *noncesA,
		[][]byte{noncesB.PubNonce[:]},
	)
	sessionB := tapMuSig2Session(
		t, signerB, keyB, keyA.PubKey.SerializeCompressed(), *noncesB,
		[][]byte{noncesA.PubNonce[:]},
	)

	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(pkt.Inputs))
	for idx, txIn := range pkt.UnsignedTx.TxIn {
		require.NotNil(t, pkt.Inputs[idx].WitnessUtxo)
		prevOuts[txIn.PreviousOutPoint] = pkt.Inputs[idx].WitnessUtxo
	}
	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(pkt.UnsignedTx, prevOutFetcher)
	sigHash, err := txscript.CalcTaprootSignatureHash(
		sigHashes, txscript.SigHashDefault, pkt.UnsignedTx, 0,
		prevOutFetcher,
	)
	require.NoError(t, err)

	partialA, err := signerA.Signer.MuSig2Sign(
		context.Background(), &signrpc.MuSig2SignRequest{
			SessionId: sessionA, MessageDigest: sigHash,
		},
	)
	require.NoError(t, err)
	partialB, err := signerB.Signer.MuSig2Sign(
		context.Background(), &signrpc.MuSig2SignRequest{
			SessionId: sessionB, MessageDigest: sigHash,
		},
	)
	require.NoError(t, err)
	require.Len(t, partialA.LocalPartialSignature, 32)
	require.Len(t, partialB.LocalPartialSignature, 32)
	require.NotEqual(t, partialA.LocalPartialSignature,
		partialB.LocalPartialSignature)

	combinedA, err := signerA.Signer.MuSig2CombineSig(
		context.Background(), &signrpc.MuSig2CombineSigRequest{
			SessionId: sessionA,
			OtherPartialSignatures: [][]byte{
				partialB.LocalPartialSignature,
			},
		},
	)
	require.NoError(t, err)
	require.True(t, combinedA.HaveAllSignatures)
	combinedB, err := signerB.Signer.MuSig2CombineSig(
		context.Background(), &signrpc.MuSig2CombineSigRequest{
			SessionId: sessionB,
			OtherPartialSignatures: [][]byte{
				partialA.LocalPartialSignature,
			},
		},
	)
	require.NoError(t, err)
	require.True(t, combinedB.HaveAllSignatures)
	require.Equal(t, combinedA.FinalSignature, combinedB.FinalSignature)
	finalSig, err := schnorr.ParseSignature(combinedA.FinalSignature)
	require.NoError(t, err)
	require.True(t, finalSig.Verify(sigHash, finalKey))

	return combinedA.FinalSignature, customAnchorMuSig2SigningEvidence{
		ParticipantPubKeys: []string{
			hex.EncodeToString(keyA.PubKey.SerializeCompressed()),
			hex.EncodeToString(keyB.PubKey.SerializeCompressed()),
		},
		PublicNonces: []string{
			hex.EncodeToString(noncesA.PubNonce[:]),
			hex.EncodeToString(noncesB.PubNonce[:]),
		},
		PartialSignatures: []string{
			hex.EncodeToString(partialA.LocalPartialSignature),
			hex.EncodeToString(partialB.LocalPartialSignature),
		},
		FinalSignature: hex.EncodeToString(combinedA.FinalSignature),
	}
}

func assertAllInputsScriptValid(t *testing.T, pkt *psbt.Packet,
	tx *wire.MsgTx) {

	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(pkt.Inputs))
	for idx, txIn := range tx.TxIn {
		require.NotNil(t, pkt.Inputs[idx].WitnessUtxo)
		prevOuts[txIn.PreviousOutPoint] = pkt.Inputs[idx].WitnessUtxo
	}
	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)
	for idx, txIn := range tx.TxIn {
		prevOut := prevOuts[txIn.PreviousOutPoint]
		vm, err := txscript.NewEngine(
			prevOut.PkScript, tx, idx, txscript.StandardVerifyFlags,
			nil, sigHashes, prevOut.Value, prevOutFetcher,
		)
		require.NoError(t, err, "input %d script engine", idx)
		require.NoError(t, vm.Execute(), "input %d script", idx)
	}
}

// testMintCustomAnchorPsbt proves the complete issue #721 lifecycle with a
// wallet-owned, caller-authored anchor: fund, prepare, externally sign,
// finalize, confirm, and spend the minted asset to a second tapd node.
func testMintCustomAnchorPsbt(t *harnessTest) {
	var (
		ctx       = context.Background()
		aliceTapd = t.tapd
		aliceLnd  = t.tapd.cfg.LndNode
		miner     = t.lndHarness.Miner()
	)

	bobLnd := t.lndHarness.NewNodeWithCoins("custom-anchor-bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	mintReq := CopyRequest(simpleAssets[0])
	mintReq.Asset.Name = "issue-721-custom-anchor-itest"
	mintReq.Asset.Amount = 100
	mintReqs := []*mintrpc.MintAssetRequest{mintReq}

	BuildMintingBatch(t.t, aliceTapd, mintReqs)

	// Use an lnd-owned internal key as the caller-selected asset anchor. The
	// output derivation fields use lnd's BIP-0043 purpose (1017') so tapd can
	// prove the locator belongs to the same wallet before committing it.
	anchorKeyResp := aliceLnd.RPC.DeriveNextKey(&walletrpc.KeyReq{
		KeyFamily: int32(asset.TaprootAssetsKeyFamily),
	})
	anchorInternalKey, err := btcec.ParsePubKey(anchorKeyResp.RawKeyBytes)
	require.NoError(t.t, err)
	anchorOutputKey := txscript.ComputeTaprootKeyNoScript(anchorInternalKey)
	anchorScript, err := txscript.PayToTaprootScript(anchorOutputKey)
	require.NoError(t.t, err)

	const anchorValue = int64(10_000)
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{
		Value:    anchorValue,
		PkScript: anchorScript,
	})
	template, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t.t, err)
	anchorKeyDesc := keychain.KeyDescriptor{
		PubKey: anchorInternalKey,
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(anchorKeyResp.KeyLoc.KeyFamily),
			Index:  uint32(anchorKeyResp.KeyLoc.KeyIndex),
		},
	}
	bip32Derivation, taprootDerivation :=
		tappsbt.Bip32DerivationFromKeyDesc(
			anchorKeyDesc, harnessNetParams.HDCoinType,
		)
	template.Outputs[0].Bip32Derivation = []*psbt.Bip32Derivation{
		bip32Derivation,
	}
	template.Outputs[0].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{taprootDerivation}
	template.Outputs[0].TaprootInternalKey =
		taprootDerivation.XOnlyPubKey
	template.Outputs[0].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x50}, Value: []byte("issue-721-anchor"),
	}}
	internalKey, err := schnorr.ParsePubKey(taprootDerivation.XOnlyPubKey)
	require.NoError(t.t, err)
	bip86OutputKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	require.Equal(t.t, schnorr.SerializePubKey(bip86OutputKey),
		anchorScript[2:])

	templateBytes, err := fn.Serialize(template)
	require.NoError(t.t, err)
	fundResp := aliceLnd.RPC.FundPsbt(&walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_CoinSelect{
			CoinSelect: &walletrpc.PsbtCoinSelect{
				Psbt: templateBytes,
				ChangeOutput: &walletrpc.PsbtCoinSelect_Add{
					Add: true,
				},
			},
		},
		Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: 2,
		},
		MinConfs:    1,
		ChangeType:  walletrpc.ChangeAddressType_CHANGE_ADDRESS_TYPE_P2TR,
		MaxFeeRatio: 1,
	})
	require.NotEmpty(t.t, fundResp.LockedUtxos)
	require.GreaterOrEqual(t.t, fundResp.ChangeOutputIndex, int32(1))

	fundedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, fundedPacket.Inputs)
	require.Equal(t.t, anchorValue,
		fundedPacket.UnsignedTx.TxOut[0].Value)
	require.Equal(t.t, anchorScript,
		fundedPacket.UnsignedTx.TxOut[0].PkScript)

	// FundPsbt initially leases every selected wallet input under its own
	// lock ID. Release those leases before FundBatch asks tapd to acquire
	// the same inputs under the custom-anchor lease ID.
	for _, lease := range fundResp.LockedUtxos {
		_, err := aliceLnd.RPC.WalletKit.ReleaseOutput(
			ctx, &walletrpc.ReleaseOutputRequest{
				Id:       lease.Id,
				Outpoint: lease.Outpoint,
			},
		)
		require.NoError(t.t, err)
	}

	fundBatchResp, err := aliceTapd.FundBatch(
		ctx, &mintrpc.FundBatchRequest{
			AnchorPsbt:             fundResp.FundedPsbt,
			AssetAnchorOutputIndex: 0,
			ChangeOutputIndex:      fundResp.ChangeOutputIndex,
		},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_PENDING,
		fundBatchResp.Batch.Batch.State,
	)

	prepareResp, err := aliceTapd.PrepareBatch(
		ctx, &mintrpc.PrepareBatchRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_COMMITTED,
		prepareResp.Batch.State,
	)
	preparedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(prepareResp.Batch.BatchPsbt), false,
	)
	require.NoError(t.t, err)

	// Preparation is allowed to replace only the selected anchor script.
	require.Equal(t.t, fundedPacket.UnsignedTx.TxIn,
		preparedPacket.UnsignedTx.TxIn)
	require.Equal(t.t, fundedPacket.Inputs, preparedPacket.Inputs)
	require.Equal(t.t, anchorValue,
		preparedPacket.UnsignedTx.TxOut[0].Value)
	require.NotEqual(t.t, anchorScript,
		preparedPacket.UnsignedTx.TxOut[0].PkScript)
	require.Equal(t.t, fundedPacket.Outputs[0].Bip32Derivation,
		preparedPacket.Outputs[0].Bip32Derivation)
	require.Equal(t.t, fundedPacket.Outputs[0].Unknowns,
		preparedPacket.Outputs[0].Unknowns)
	require.Nil(t.t, preparedPacket.Outputs[0].TaprootInternalKey)
	require.Nil(t.t, preparedPacket.Outputs[0].TaprootBip32Derivation)
	for idx := 1; idx < len(fundedPacket.UnsignedTx.TxOut); idx++ {
		require.Equal(t.t, fundedPacket.UnsignedTx.TxOut[idx],
			preparedPacket.UnsignedTx.TxOut[idx])
		require.Equal(t.t, fundedPacket.Outputs[idx],
			preparedPacket.Outputs[idx])
	}

	// WalletKit signs the wallet input and local PSBT finalization is used
	// for compatibility with the remote-signing itest mode.
	signedPacket := FinalizePacket(t.t, aliceLnd.RPC, preparedPacket)
	signedBytes, err := fn.Serialize(signedPacket)
	require.NoError(t.t, err)
	ctxFinalize, cancelFinalize := context.WithTimeout(ctx, defaultWaitTimeout)
	finalizeResp, err := aliceTapd.FinalizeBatch(
		ctxFinalize, &mintrpc.FinalizeBatchRequest{
			SignedPsbt: signedBytes,
		},
	)
	cancelFinalize()
	require.NoError(t.t, err)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_BROADCAST,
		finalizeResp.Batch.State,
	)

	hashes, err := WaitForNTxsInMempool(miner, 1, defaultWaitTimeout)
	require.NoError(t.t, err)
	require.Len(t.t, hashes, 1)
	block := MineBlocks(t.t, miner, 1, 1)[0]
	ctxWait, cancelWait := context.WithTimeout(ctx, defaultWaitTimeout)
	defer cancelWait()
	WaitForBatchState(
		t.t, ctxWait, aliceTapd, defaultWaitTimeout,
		finalizeResp.Batch.BatchKey,
		mintrpc.BatchState_BATCH_STATE_FINALIZED,
	)
	mintedAssets := AssertAssetsMinted(
		t.t, aliceTapd, mintReqs, *hashes[0], block.BlockHash(),
	)
	require.Len(t.t, mintedAssets, 1)
	mintedAsset := mintedAssets[0]

	const sendAmount = uint64(40)
	bobAddr, err := bobTapd.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: mintedAsset.AssetGenesis.AssetId,
		Amt:     sendAmount,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bobTapd, mintedAsset, bobAddr)

	sendResp, sendEvents := sendAssetsToAddr(t, aliceTapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, miner, aliceTapd, sendResp,
		mintedAsset.AssetGenesis.AssetId,
		[]uint64{mintedAsset.Amount - sendAmount, sendAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)
	AssertBalanceByID(
		t.t, bobTapd, mintedAsset.AssetGenesis.AssetId, sendAmount,
	)
}
