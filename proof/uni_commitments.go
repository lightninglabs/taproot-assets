package proof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrSignatureVerificationFailed is an error that is returned when the
	// signature verification of the UniCommitments fails.
	ErrSignatureVerificationFailed = errors.New(
		"signature verification failed",
	)
)

// UniCommitmentVersion is a type that represents the version of the
// UniCommitments.
type UniCommitmentVersion uint8

const (
	// UniCommitmentV0 is the first version of the UniCommitments.
	UniCommitmentV0 UniCommitmentVersion = 0
)

// Record returns a TLV record that can be used to encode/decode a
// UniCommitmentVersion to/from a TLV stream.
func (v *UniCommitmentVersion) Record() tlv.Record {
	// We set the type to zero here because the type parameter in
	// tlv.RecordT will be used as the actual type.
	return tlv.MakeStaticRecord(
		0, v, 1, UniCommitmentVersionEncoder,
		UniCommitmentVersionDecoder,
	)
}

// UniCommitmentParams is a struct that holds the parameters for universe
// commitments.
type UniCommitmentParams struct {
	Version            tlv.RecordT[tlv.TlvType0, UniCommitmentVersion]
	PreCommitmentIndex tlv.RecordT[tlv.TlvType2, uint32]
}

// NewUniCommitmentParams creates a new UniCommitmentParams instance with the
// given version and pre-commitment index.
func NewUniCommitmentParams(version UniCommitmentVersion,
	preCommitmentIndex uint32) *UniCommitmentParams {

	return &UniCommitmentParams{
		Version: tlv.NewRecordT[tlv.TlvType0](version),
		PreCommitmentIndex: tlv.NewPrimitiveRecord[tlv.TlvType2](
			preCommitmentIndex,
		),
	}
}

// Encode serializes the UniCommitmentParams to the given io.Writer.
func (p *UniCommitmentParams) Encode(w io.Writer) error {
	records := []tlv.Record{
		p.Version.Record(),
		p.PreCommitmentIndex.Record(),
	}

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the UniCommitmentParams from the given io.Reader.
func (p *UniCommitmentParams) Decode(r io.Reader) error {
	tlvStream, err := tlv.NewStream(
		p.Version.Record(),
		p.PreCommitmentIndex.Record(),
	)
	if err != nil {
		return err
	}

	return tlvStream.DecodeP2P(r)
}

// Bytes returns the serialized UniCommitmentParams record.
func (p *UniCommitmentParams) Bytes() []byte {
	var buf bytes.Buffer
	_ = p.Encode(&buf)
	return buf.Bytes()
}

// Record creates a Record out of a UniCommitmentParams.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (p *UniCommitmentParams) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := UniCommitmentParamsEncoder(&buf, p, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}
	return tlv.MakeDynamicRecord(
		0, p, size, UniCommitmentParamsEncoder,
		UniCommitmentParamsDecoder,
	)
}

// UniCommitments is a struct that holds the universe commitment parameters and
// the authorized signature over those parameters.
type UniCommitments struct {
	Params tlv.OptionalRecordT[tlv.TlvType0, UniCommitmentParams]
	Sig    tlv.RecordT[tlv.TlvType2, lnwire.Sig]
}

// NewUniCommitments creates a new UniCommitments instance with the given
// parameters and signature.
func NewUniCommitments(params *UniCommitmentParams,
	sig lnwire.Sig) *UniCommitments {

	var paramsRecord tlv.OptionalRecordT[tlv.TlvType0, UniCommitmentParams]
	if params != nil {
		paramsRecord = tlv.SomeRecordT[tlv.TlvType0](
			tlv.NewRecordT[tlv.TlvType0](*params),
		)
	}

	return &UniCommitments{
		Params: paramsRecord,
		Sig:    tlv.NewRecordT[tlv.TlvType2](sig),
	}
}

// Encode serializes the UniCommitments to the given io.Writer.
func (p *UniCommitments) Encode(w io.Writer) error {
	records := []tlv.Record{
		p.Sig.Record(),
	}

	p.Params.WhenSome(
		func(r tlv.RecordT[tlv.TlvType0, UniCommitmentParams]) {
			records = append(records, r.Record())
		},
	)

	tlv.SortRecords(records)

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the UniCommitments from the given io.Reader.
func (p *UniCommitments) Decode(r io.Reader) error {
	params := p.Params.Zero()

	tlvStream, err := tlv.NewStream(
		params.Record(),
		p.Sig.Record(),
	)
	if err != nil {
		return err
	}

	tlvs, err := tlvStream.DecodeWithParsedTypesP2P(r)
	if err != nil {
		return err
	}

	if _, ok := tlvs[params.TlvType()]; ok {
		p.Params = tlv.SomeRecordT(params)
	}

	// We need to force the signature type to be a Schnorr signature for the
	// unit tests to pass.
	var emptySig lnwire.Sig
	if p.Sig.Val != emptySig {
		p.Sig.Val.ForceSchnorr()
	}

	return nil
}

// Bytes returns the serialized UniCommitments record.
func (p *UniCommitments) Bytes() []byte {
	var buf bytes.Buffer
	_ = p.Encode(&buf)
	return buf.Bytes()
}

// VerificationDigest returns the digest of the UniCommitments that should be
// used for verification of the signature.
func (p *UniCommitments) VerificationDigest(mintPoint wire.OutPoint) [32]byte {
	hash := sha256.New()
	_ = wire.WriteOutPoint(hash, 0, 0, &mintPoint)
	p.Params.ValOpt().WhenSome(func(params UniCommitmentParams) {
		_ = params.Encode(hash)
	})

	return ([32]byte)(hash.Sum(nil))
}

// Record creates a Record out of a UniCommitments.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (p *UniCommitments) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := UniCommitmentParamsEncoder(&buf, p, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}
	return tlv.MakeDynamicRecord(
		0, p, size, UniCommitmentParamsEncoder,
		UniCommitmentParamsDecoder,
	)
}

// Sign creates a signed commitment over the UniCommitments.
func (p *UniCommitments) Sign(ctx context.Context,
	signer lndclient.SignerClient, key keychain.KeyLocator,
	mintPoint wire.OutPoint) error {

	digest := p.VerificationDigest(mintPoint)
	sig, err := signer.SignMessage(
		ctx, digest[:], key, lndclient.SignSchnorr(nil),
	)
	if err != nil {
		return err
	}

	schnorrSig, err := lnwire.NewSigFromSchnorrRawSignature(sig)
	if err != nil {
		return err
	}

	p.Sig.Val = schnorrSig

	return nil
}

// Verify verifies the signature of the UniCommitments.
func (p *UniCommitments) Verify(mintPoint wire.OutPoint,
	key *btcec.PublicKey) error {

	digest := p.VerificationDigest(mintPoint)

	sig, err := p.Sig.Val.ToSignature()
	if err != nil {
		return err
	}

	if !sig.Verify(digest[:], key) {
		return ErrSignatureVerificationFailed
	}

	return nil
}
