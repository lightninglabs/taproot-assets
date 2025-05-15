package rpcutils

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
)

// MarshalTxProof converts a TxProof to its gRPC representation.
func MarshalTxProof(
	p proof.TxProof) (*mboxrpc.BitcoinMerkleInclusionProof, error) {

	serialize := func(serFn func(at io.Writer) error) ([]byte, error) {
		var buf bytes.Buffer
		if err := serFn(&buf); err != nil {
			return nil, fmt.Errorf("error serializing: %w", err)
		}
		return buf.Bytes(), nil
	}

	rawTxData, err := serialize(p.MsgTx.Serialize)
	if err != nil {
		return nil, fmt.Errorf("error serializing raw tx data: %w", err)
	}

	rawBlockHeaderData, err := serialize(p.BlockHeader.Serialize)
	if err != nil {
		return nil, fmt.Errorf("error serializing raw block header "+
			"data: %w", err)
	}

	txMerkleProof := &mboxrpc.MerkleProof{
		SiblingHashes: make([][]byte, len(p.MerkleProof.Nodes)),
		Bits:          make([]bool, len(p.MerkleProof.Bits)),
	}
	for idx, node := range p.MerkleProof.Nodes {
		txMerkleProof.SiblingHashes[idx] = node[:]
	}
	copy(txMerkleProof.Bits, p.MerkleProof.Bits)

	return &mboxrpc.BitcoinMerkleInclusionProof{
		RawTxData:          rawTxData,
		RawBlockHeaderData: rawBlockHeaderData,
		BlockHeight:        p.BlockHeight,
		MerkleProof:        txMerkleProof,
		ClaimedOutpoint: &mboxrpc.Outpoint{
			TxidHex: p.ClaimedOutPoint.Hash.String(),
			Index:   p.ClaimedOutPoint.Index,
		},
	}, nil
}

// UnmarshalTxProof converts a gRPC TxProof to its internal representation.
func UnmarshalTxProof(
	rpcProof *mboxrpc.BitcoinMerkleInclusionProof) (*proof.TxProof, error) {

	var p proof.TxProof
	err := p.MsgTx.Deserialize(bytes.NewReader(rpcProof.RawTxData))
	if err != nil {
		return nil, fmt.Errorf("error decoding raw tx data: %w", err)
	}

	err = p.BlockHeader.Deserialize(
		bytes.NewReader(rpcProof.RawBlockHeaderData),
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding raw block header "+
			"data: %w", err)
	}

	p.BlockHeight = rpcProof.BlockHeight
	if p.BlockHeight == 0 {
		return nil, fmt.Errorf("block height is missing")
	}

	if rpcProof.MerkleProof == nil {
		return nil, fmt.Errorf("merkle proof is missing")
	}

	mp := rpcProof.MerkleProof
	if len(mp.SiblingHashes) == 0 {
		return nil, fmt.Errorf("merkle proof sibling hashes are " +
			"missing")
	}

	if len(mp.SiblingHashes) != len(mp.Bits) {
		return nil, fmt.Errorf("merkle proof sibling hashes and " +
			"bits length mismatch")
	}

	p.MerkleProof.Nodes = make([]chainhash.Hash, len(mp.SiblingHashes))
	for idx, siblingHash := range mp.SiblingHashes {
		hash, err := chainhash.NewHash(siblingHash)
		if err != nil {
			return nil, fmt.Errorf("error decoding sibling "+
				"hash: %w", err)
		}

		p.MerkleProof.Nodes[idx] = *hash
	}

	p.MerkleProof.Bits = make([]bool, len(mp.Bits))
	copy(p.MerkleProof.Bits, mp.Bits)

	if rpcProof.ClaimedOutpoint == nil {
		return nil, fmt.Errorf("claimed outpoint is missing")
	}

	opHash, err := chainhash.NewHashFromStr(
		rpcProof.ClaimedOutpoint.TxidHex,
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding outpoint txid: %w",
			err)
	}

	p.ClaimedOutPoint = wire.OutPoint{
		Hash:  *opHash,
		Index: rpcProof.ClaimedOutpoint.Index,
	}

	return &p, nil
}
