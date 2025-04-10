package authmailbox

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
)

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
	p.MerkleProof.Bits = make([]bool, len(mp.SiblingHashes))
	for idx, siblingHash := range mp.SiblingHashes {
		hash, err := chainhash.NewHash(siblingHash)
		if err != nil {
			return nil, fmt.Errorf("error decoding sibling "+
				"hash: %w", err)
		}

		p.MerkleProof.Nodes[idx] = *hash
		p.MerkleProof.Bits[idx] = mp.Bits[idx]
	}

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
