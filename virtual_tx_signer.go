package taprootassets

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapscript"
)

// LndRpcVirtualTxSigner is an implementation of the tapscript.Signer
// interface backed by an active lnd node.
type LndRpcVirtualTxSigner struct {
	lnd *lndclient.LndServices
}

// NewLndRpcVirtualTxSigner returns a new tx signer instance backed by the
// passed connection to a remote lnd node.
func NewLndRpcVirtualTxSigner(lnd *lndclient.LndServices) *LndRpcVirtualTxSigner {
	return &LndRpcVirtualTxSigner{
		lnd: lnd,
	}
}

// Save sigHash to a file named sighash.hex, clearing any previous contents.
func saveSigHashToFile(sigHash []byte) error {
	// Open the file with write-only mode, create it if it doesn't exist, and truncate it to clear existing content.
	file, err := os.OpenFile("sighash.hex", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open/create file: %w", err)
	}
	defer file.Close()

	// Write the sigHash as a hex string to the file.
	_, err = file.WriteString(hex.EncodeToString(sigHash))
	if err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	fmt.Println("SigHash successfully written to sighash.hex")
	return nil
}

// Helper function to read the override signature from a file.
func readOverrideSignature(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// If the file doesn't exist, return an empty string.
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

// SignVirtualTx generates a signature according to the passed signing
// descriptor and virtual TX.
func (l *LndRpcVirtualTxSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	// So that we can sign the sighash with external clients, lets
	// calculate the sighash here and write it to a file for external clients
	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(
		tx, prevOutFetcher,
	)
	sigHash, err := txscript.CalcTaprootSignatureHash(
		sigHashes, txscript.SigHashDefault, tx, 0, prevOutFetcher,
	)
	fmt.Printf("SignVirtualTx: sigHash: %x\n", sigHash)
	if err = saveSigHashToFile(sigHash); err != nil {
		return nil, fmt.Errorf("failed to save sigHash to file: %w", err)
	}

	// Try to read the override signature from sighash.hex.
	overrideSigHex, err := readOverrideSignature("signature.hex")
	if err != nil {
		return nil, fmt.Errorf("failed to read override signature: %w", err)
	}

	var sigs [][]byte
	if overrideSigHex != "" {
		// Decode the override signature from hex.
		sig, err := hex.DecodeString(overrideSigHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode override signature: %w", err)
		}
		sigs = append(sigs, sig)
		fmt.Printf("Used override signature from signature.hex: %x\n", sigs[0])
	} else {
		// legacy flow
		sigs, err = l.lnd.Signer.SignOutputRaw(
			context.Background(), tx, []*lndclient.SignDescriptor{signDesc},
			[]*wire.TxOut{prevOut},
		)
		if err != nil {
			return nil, err
		}
	}

	// Our signer should only ever produce one signature or fail before this
	// point, so accessing the signature directly is safe.
	virtualTxSig, err := schnorr.ParseSignature(sigs[0])
	if err != nil {
		return nil, err
	}

	return virtualTxSig, nil
}

// Compile time assertions to ensure LndRpcVirtualTxSigner meets the
// tapscript.Signer and asset.GenesisSigner interfaces.
var _ tapscript.Signer = (*LndRpcVirtualTxSigner)(nil)

var _ asset.GenesisSigner = (*LndRpcVirtualTxSigner)(nil)
