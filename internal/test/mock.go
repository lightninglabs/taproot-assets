package test

import (
	"bytes"
	"context"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
)

var (
	testSignature    = []byte{55, 66, 77, 88, 99}
	testSignatureMsg = "test"
)

// SignOutputRawRequest contains input data for a tx signing request.
type SignOutputRawRequest struct {
	Tx              *wire.MsgTx
	SignDescriptors []*lndclient.SignDescriptor
}

func NewMockSigner() *MockSigner {
	return &MockSigner{
		SignOutputRawChannel: make(chan SignOutputRawRequest),
		Signature:            testSignature,
		SignatureMsg:         testSignatureMsg,
	}
}

type MockSigner struct {
	lndclient.SignerClient

	SignOutputRawChannel chan SignOutputRawRequest

	Signature    []byte
	SignatureMsg string
}

func (s *MockSigner) RawClientWithMacAuth(
	ctx context.Context) (context.Context, time.Duration,
	signrpc.SignerClient) {

	return ctx, 0, nil
}

func (s *MockSigner) SignOutputRaw(_ context.Context, tx *wire.MsgTx,
	signDescriptors []*lndclient.SignDescriptor,
	_ []*wire.TxOut) ([][]byte, error) {

	s.SignOutputRawChannel <- SignOutputRawRequest{
		Tx:              tx,
		SignDescriptors: signDescriptors,
	}

	rawSigs := [][]byte{{1, 2, 3}}

	return rawSigs, nil
}

func (s *MockSigner) SignMessage(_ context.Context, _ []byte,
	_ keychain.KeyLocator, _ ...lndclient.SignMessageOption) ([]byte,
	error) {

	return s.Signature, nil
}

func (s *MockSigner) VerifyMessage(_ context.Context, msg, sig []byte,
	_ [33]byte, _ ...lndclient.VerifyMessageOption) (bool, error) {

	mockAssertion := bytes.Equal(sig, s.Signature)

	return mockAssertion, nil
}

func (s *MockSigner) DeriveSharedKey(context.Context, *btcec.PublicKey,
	*keychain.KeyLocator) ([32]byte, error) {

	return [32]byte{4, 5, 6}, nil
}

// MuSig2CreateSession creates a new MuSig2 signing session using the local
// key identified by the key locator. The complete list of all public keys of
// all signing parties must be provided, including the public key of the local
// signing key. If nonces of other parties are already known, they can be
// submitted as well to reduce the number of method calls necessary later on.
func (s *MockSigner) MuSig2CreateSession(context.Context, input.MuSig2Version,
	*keychain.KeyLocator, [][]byte, ...lndclient.MuSig2SessionOpts) (
	*input.MuSig2SessionInfo, error) {

	return nil, nil
}

// MuSig2RegisterNonces registers one or more public nonces of other signing
// participants for a session identified by its ID. This method returns true
// once we have all nonces for all other signing participants.
func (s *MockSigner) MuSig2RegisterNonces(context.Context, [32]byte,
	[][66]byte) (bool, error) {

	return false, nil
}

// MuSig2Sign creates a partial signature using the local signing key
// that was specified when the session was created. This can only be
// called when all public nonces of all participants are known and have
// been registered with the session. If this node isn't responsible for
// combining all the partial signatures, then the cleanup parameter
// should be set, indicating that the session can be removed from memory
// once the signature was produced.
func (s *MockSigner) MuSig2Sign(context.Context, [32]byte, [32]byte,
	bool) ([]byte, error) {

	return nil, nil
}

// MuSig2CombineSig combines the given partial signature(s) with the
// local one, if it already exists. Once a partial signature of all
// participants is registered, the final signature will be combined and
// returned.
func (s *MockSigner) MuSig2CombineSig(context.Context, [32]byte,
	[][]byte) (bool, []byte, error) {

	return false, nil, nil
}

// MuSig2Cleanup removes a session from memory to free up resources.
func (s *MockSigner) MuSig2Cleanup(context.Context, [32]byte) error {
	return nil
}
