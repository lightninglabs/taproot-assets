package tapchannel

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/vm"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

// shutdownErr is used in multiple spots when exiting the sig batch processor.
var shutdownErr = fmt.Errorf("tapd is shutting down")

// VirtualPacketSigner is an interface that can be used to sign virtual packets.
type VirtualPacketSigner interface {
	// SignVirtualPacket signs the virtual transaction of the given packet
	// and returns the input indexes that were signed.
	SignVirtualPacket(vPkt *tappsbt.VPacket,
		signOpts ...tapfreighter.SignVirtualPacketOption) ([]uint32,
		error)
}

// LeafSignerConfig defines the configuration for the auxiliary leaf signer.
type LeafSignerConfig struct {
	// ChainParams are the chain parameters of the network the signer is
	// operating on.
	ChainParams *address.ChainParams

	// Signer is the backing wallet that can sign virtual packets.
	Signer VirtualPacketSigner
}

// AuxLeafSigner is a Taproot Asset auxiliary leaf signer that can be used to
// sign auxiliary leaves for Taproot Asset channels.
type AuxLeafSigner struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *LeafSignerConfig

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewAuxLeafSigner creates a new Taproot Asset auxiliary leaf signer based on
// the passed config.
func NewAuxLeafSigner(cfg *LeafSignerConfig) *AuxLeafSigner {
	return &AuxLeafSigner{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new aux leaf signer.
func (s *AuxLeafSigner) Start() error {
	var startErr error
	s.startOnce.Do(func() {
		log.Info("Starting aux leaf signer")
	})
	return startErr
}

// Stop signals for a aux leaf signer to gracefully exit.
func (s *AuxLeafSigner) Stop() error {
	var stopErr error
	s.stopOnce.Do(func() {
		log.Info("Stopping aux leaf signer")

		close(s.Quit)
		s.Wg.Wait()
	})

	return stopErr
}

// SubmitSecondLevelSigBatch takes a batch of aux sign jobs and processes them
// asynchronously.
func (s *AuxLeafSigner) SubmitSecondLevelSigBatch(
	chanState lnwallet.AuxChanState, commitTx *wire.MsgTx,
	jobs []lnwallet.AuxSigJob) error {

	s.Wg.Add(1)
	go s.processAuxSigBatch(chanState, commitTx, jobs)

	return nil
}

// PackSigs takes a series of aux signatures and packs them into a single blob
// that can be sent alongside the CommitSig messages.
func PackSigs(sigBlob []lfn.Option[tlv.Blob]) lfn.Result[lfn.Option[tlv.Blob]] {
	type returnType = lfn.Option[tlv.Blob]

	htlcSigs := make([][]*cmsg.AssetSig, len(sigBlob))
	for idx := range sigBlob {
		err := lfn.MapOptionZ(
			sigBlob[idx], func(sigBlob tlv.Blob) error {
				assetSigs, err := cmsg.DecodeAssetSigListRecord(
					sigBlob,
				)
				if err != nil {
					return err
				}

				htlcSigs[idx] = assetSigs.Sigs

				return nil
			},
		)
		if err != nil {
			return lfn.Err[returnType](fmt.Errorf("error "+
				"decoding asset sig list record: %w", err))
		}
	}

	commitSig := cmsg.NewCommitSig(htlcSigs)

	var buf bytes.Buffer
	if err := commitSig.Encode(&buf); err != nil {
		return lfn.Err[returnType](fmt.Errorf("error encoding "+
			"commit sig: %w", err))
	}

	return lfn.Ok(lfn.Some(buf.Bytes()))
}

// UnpackSigs takes a packed blob of signatures and returns the original
// signatures for each HTLC, keyed by HTLC index.
func UnpackSigs(blob lfn.Option[tlv.Blob]) lfn.Result[[]lfn.Option[tlv.Blob]] {
	type returnType = []lfn.Option[tlv.Blob]

	if blob.IsNone() {
		return lfn.Ok[returnType](nil)
	}

	commitSig, err := cmsg.DecodeCommitSig(blob.UnsafeFromSome())
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("error decoding commit "+
			"sig: %w", err))
	}

	htlcSigRec := commitSig.HtlcPartialSigs.Val.HtlcPartialSigs
	htlcSigs := make([]lfn.Option[tlv.Blob], len(htlcSigRec))
	for idx := range htlcSigRec {
		htlcSigs[idx] = lfn.Some(htlcSigRec[idx].Bytes())
	}

	return lfn.Ok(htlcSigs)
}

// VerifySecondLevelSigs attempts to synchronously verify a batch of aux sig
// jobs.
func VerifySecondLevelSigs(chainParams *address.ChainParams,
	chanState lnwallet.AuxChanState, commitTx *wire.MsgTx,
	verifyJobs []lnwallet.AuxVerifyJob) error {

	for idx := range verifyJobs {
		verifyJob := verifyJobs[idx]

		// If there is no signature blob, this isn't a custom channel.
		if verifyJob.SigBlob.IsNone() {
			continue
		}

		assetSigs, err := cmsg.DecodeAssetSigListRecord(
			verifyJob.SigBlob.UnsafeFromSome(),
		)
		if err != nil {
			return fmt.Errorf("error decoding asset sig list "+
				"record: %w", err)
		}

		// If there is no commit blob, this isn't a custom channel.
		if verifyJob.CommitBlob.IsNone() {
			continue
		}

		com, err := cmsg.DecodeCommitment(
			verifyJob.CommitBlob.UnsafeFromSome(),
		)
		if err != nil {
			return fmt.Errorf("error decoding commitment: %w", err)
		}

		var (
			htlcs       = com.OutgoingHtlcAssets.Val.HtlcOutputs
			htlcOutputs []*cmsg.AssetOutput
		)
		if verifyJob.Incoming {
			htlcs = com.IncomingHtlcAssets.Val.HtlcOutputs
		}
		for outIndex := range htlcs {
			if outIndex == verifyJob.HTLC.HtlcIndex {
				htlcOutputs = htlcs[outIndex].Outputs

				break
			}
		}

		// If the HTLC doesn't have any asset outputs, it's not an
		// asset HTLC, so we can skip it.
		if len(htlcOutputs) == 0 {
			continue
		}

		err = verifyHtlcSignature(
			chainParams, chanState, commitTx,
			verifyJobs[idx].KeyRing, assetSigs.Sigs, htlcOutputs,
			verifyJobs[idx].BaseAuxJob,
		)
		if err != nil {
			return fmt.Errorf("error verifying second level sig: "+
				"%w", err)
		}
	}

	return nil
}

// processAuxSigBatch processes a batch of aux sign jobs asynchronously.
//
// NOTE: This method must be called as a goroutine.
func (s *AuxLeafSigner) processAuxSigBatch(chanState lnwallet.AuxChanState,
	commitTx *wire.MsgTx, sigJobs []lnwallet.AuxSigJob) {

	defer s.Wg.Done()

	log.Tracef("Processing %d aux sig jobs", len(sigJobs))
	for idx := range sigJobs {
		sigJob := sigJobs[idx]
		respondErr := func(err error) {
			log.Errorf("Error processing aux sig job: %v", err)

			sigJob.Resp <- lnwallet.AuxSigJobResp{
				Err: err,
			}
		}

		// Check for cancel or quit signals before beginning the job.
		select {
		case <-sigJob.Cancel:
			continue
		case <-s.Quit:
			respondErr(shutdownErr)
			return
		default:
		}

		// If there is no commit blob, this isn't a custom channel. We
		// still need to signal the job as done though, even if we don't
		// have a signature to return.
		if sigJob.CommitBlob.IsNone() {
			select {
			case sigJob.Resp <- lnwallet.AuxSigJobResp{
				HtlcIndex: sigJob.HTLC.HtlcIndex,
			}:
				continue
			case <-sigJob.Cancel:
				continue
			case <-s.Quit:
				respondErr(shutdownErr)
				return
			}
		}

		com, err := cmsg.DecodeCommitment(
			sigJob.CommitBlob.UnsafeFromSome(),
		)
		if err != nil {
			respondErr(fmt.Errorf("error decoding commitment: %w",
				err))
			return
		}

		var (
			htlcs       = com.OutgoingHtlcAssets.Val.HtlcOutputs
			htlcOutputs []*cmsg.AssetOutput
		)
		if sigJob.Incoming {
			htlcs = com.IncomingHtlcAssets.Val.HtlcOutputs
		}
		for outIndex := range htlcs {
			if outIndex == sigJob.HTLC.HtlcIndex {
				htlcOutputs = htlcs[outIndex].Outputs

				break
			}
		}

		// If the HTLC doesn't have any asset outputs, it's not an
		// asset HTLC, so we can skip it.
		if len(htlcOutputs) == 0 {
			select {
			case sigJob.Resp <- lnwallet.AuxSigJobResp{
				HtlcIndex: sigJob.HTLC.HtlcIndex,
			}:
				continue
			case <-sigJob.Cancel:
				continue
			case <-s.Quit:
				respondErr(shutdownErr)
				return
			}
		}

		resp, err := s.generateHtlcSignature(
			chanState, commitTx, htlcOutputs, sigJob.SignDesc,
			sigJob.BaseAuxJob,
		)
		if err != nil {
			respondErr(fmt.Errorf("error generating HTLC "+
				"signature: %w", err))
			return
		}

		// Success!
		log.Tracef("Generated HTLC signature for HTLC with index %d",
			sigJob.HTLC.HtlcIndex)

		select {
		case sigJob.Resp <- resp:
		case <-sigJob.Cancel:
			continue
		case <-s.Quit:
			respondErr(shutdownErr)
			return
		}
	}
}

// verifyHtlcSignature verifies the HTLC signature in the commitment transaction
// described by the sign job.
func verifyHtlcSignature(chainParams *address.ChainParams,
	chanState lnwallet.AuxChanState, commitTx *wire.MsgTx,
	keyRing lnwallet.CommitmentKeyRing, sigs []*cmsg.AssetSig,
	htlcOutputs []*cmsg.AssetOutput, baseJob lnwallet.BaseAuxJob) error {

	// If we're validating a signature for an outgoing HTLC, then it's an
	// outgoing HTLC for the remote party, so we'll need to sign it with the
	// proper lock time.
	var htlcTimeout fn.Option[uint32]
	if !baseJob.Incoming {
		htlcTimeout = fn.Some(baseJob.HTLC.Timeout)
	}

	vPackets, err := htlcSecondLevelPacketsFromCommit(
		chainParams, chanState, commitTx, baseJob.KeyRing, htlcOutputs,
		baseJob, htlcTimeout, baseJob.HTLC.HtlcIndex,
	)
	if err != nil {
		return fmt.Errorf("error generating second level packets: %w",
			err)
	}

	for idx, vPacket := range vPackets {
		// This is a signature for a second-level HTLC, which always
		// only has one input and one output. But there might be
		// multiple asset IDs, which is why we might have multiple
		// signatures. But the order of the signatures and virtual
		// packets are expected to align.
		vIn := vPacket.Inputs[0]
		vOut := vPacket.Outputs[0]
		sig := sigs[idx]

		// Construct input set from the single input asset.
		prevAssets := commitment.InputSet{
			vIn.PrevID: vIn.Asset(),
		}
		newAsset := vOut.Asset

		// Now that we know we're not dealing with a genesis state
		// transition, we'll map our set of asset inputs and outputs to
		// the 1-input 1-output virtual transaction.
		virtualTx, _, err := tapscript.VirtualTx(newAsset, prevAssets)
		if err != nil {
			return err
		}

		// We are always verifying the signature of the remote party,
		// which are for our commitment transaction.
		const whoseCommit = lntypes.Local

		htlcScript, err := lnwallet.GenTaprootHtlcScript(
			baseJob.Incoming, whoseCommit, baseJob.HTLC.Timeout,
			baseJob.HTLC.RHash, &keyRing,
			lfn.None[txscript.TapLeaf](),
		)
		if err != nil {
			return fmt.Errorf("error creating HTLC script to "+
				"verify second level: %w", err)
		}

		leafToVerify := txscript.TapLeaf{
			Script:      htlcScript.WitnessScriptToSign(),
			LeafVersion: txscript.BaseLeafVersion,
		}
		validator := &schnorrSigValidator{
			pubKey:     *keyRing.RemoteHtlcKey,
			tapLeaf:    lfn.Some(leafToVerify),
			signMethod: input.TaprootScriptSpendSignMethod,
		}

		return validator.validateSchnorrSig(
			virtualTx, vIn.Asset(), newAsset, uint32(idx),
			txscript.SigHashType(sig.SigHashType.Val), sig.Sig.Val,
		)
	}

	return nil
}

// applySignDescToVIn applies the sign descriptor to the virtual input. This
// entails updating all the input bip32, taproot, and witness fields with the
// information from the sign descriptor. This function returns the public key
// that should be used to verify the generated signature, and also the leaf to
// be signed.
func applySignDescToVIn(signDesc input.SignDescriptor, vIn *tappsbt.VInput,
	chainParams *address.ChainParams,
	tapscriptRoot []byte) (btcec.PublicKey, txscript.TapLeaf) {

	leafToSign := txscript.TapLeaf{
		Script:      signDesc.WitnessScript,
		LeafVersion: txscript.BaseLeafVersion,
	}
	vIn.TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			Script:      leafToSign.Script,
			LeafVersion: leafToSign.LeafVersion,
		},
	}

	deriv, trDeriv := tappsbt.Bip32DerivationFromKeyDesc(
		signDesc.KeyDesc, chainParams.HDCoinType,
	)
	vIn.Bip32Derivation = []*psbt.Bip32Derivation{deriv}
	vIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		trDeriv,
	}
	vIn.TaprootBip32Derivation[0].LeafHashes = [][]byte{
		fn.ByteSlice(leafToSign.TapHash()),
	}
	vIn.SighashType = signDesc.HashType
	vIn.TaprootMerkleRoot = tapscriptRoot

	// Apply single or double tweaks if present in the sign
	// descriptor. At the same time, we apply the tweaks to a copy
	// of the public key, so we can validate the produced signature.
	signingKey := signDesc.KeyDesc.PubKey
	if len(signDesc.SingleTweak) > 0 {
		key := btcwallet.PsbtKeyTypeInputSignatureTweakSingle
		vIn.Unknowns = append(vIn.Unknowns, &psbt.Unknown{
			Key:   key,
			Value: signDesc.SingleTweak,
		})

		signingKey = input.TweakPubKeyWithTweak(
			signingKey, signDesc.SingleTweak,
		)
	}
	if signDesc.DoubleTweak != nil {
		key := btcwallet.PsbtKeyTypeInputSignatureTweakDouble
		vIn.Unknowns = append(vIn.Unknowns, &psbt.Unknown{
			Key:   key,
			Value: signDesc.DoubleTweak.Serialize(),
		})

		signingKey = input.DeriveRevocationPubkey(
			signingKey, signDesc.DoubleTweak.PubKey(),
		)
	}

	return *signingKey, leafToSign
}

// generateHtlcSignature generates the signature for the HTLC output in the
// commitment transaction described by the sign job.
func (s *AuxLeafSigner) generateHtlcSignature(chanState lnwallet.AuxChanState,
	commitTx *wire.MsgTx, htlcOutputs []*cmsg.AssetOutput,
	signDesc input.SignDescriptor,
	baseJob lnwallet.BaseAuxJob) (lnwallet.AuxSigJobResp, error) {

	// If we're generating a signature for an incoming HTLC, then it's an
	// outgoing HTLC for the remote party, so we'll need to sign it with the
	// proper lock time.
	var htlcTimeout fn.Option[uint32]
	if baseJob.Incoming {
		htlcTimeout = fn.Some(baseJob.HTLC.Timeout)
	}

	vPackets, err := htlcSecondLevelPacketsFromCommit(
		s.cfg.ChainParams, chanState, commitTx, baseJob.KeyRing,
		htlcOutputs, baseJob, htlcTimeout, baseJob.HTLC.HtlcIndex,
	)
	if err != nil {
		return lnwallet.AuxSigJobResp{}, fmt.Errorf("error generating "+
			"second level packets: %w", err)
	}

	// We are always signing the commitment transaction of the remote party,
	// which is why we set whoseCommit to remote.
	const whoseCommit = lntypes.Remote

	htlcScript, err := lnwallet.GenTaprootHtlcScript(
		baseJob.Incoming, whoseCommit, baseJob.HTLC.Timeout,
		baseJob.HTLC.RHash, &baseJob.KeyRing,
		lfn.None[txscript.TapLeaf](),
	)
	if err != nil {
		return lnwallet.AuxSigJobResp{}, fmt.Errorf("error creating "+
			"HTLC script: %w", err)
	}

	tapscriptRoot := htlcScript.TapscriptRoot

	var sigs []*cmsg.AssetSig
	for _, vPacket := range vPackets {
		vIn := vPacket.Inputs[0]

		signingKey, leafToSign := applySignDescToVIn(
			signDesc, vIn, s.cfg.ChainParams, tapscriptRoot,
		)

		// We can now sign this virtual packet, as we've given the
		// wallet internal signer everything it needs to locate the key
		// and decide how to sign. Since the signature is only one of
		// two required, we can't use the default validator that would
		// check the full witness. Instead, we use a custom Schnorr
		// signature validator to validate the single signature we
		// produced.
		signed, err := s.cfg.Signer.SignVirtualPacket(
			vPacket, tapfreighter.SkipInputProofVerify(),
			tapfreighter.WithValidator(&schnorrSigValidator{
				pubKey:     signingKey,
				tapLeaf:    lfn.Some(leafToSign),
				signMethod: input.TaprootScriptSpendSignMethod,
			}),
		)
		if err != nil {
			return lnwallet.AuxSigJobResp{}, fmt.Errorf("error "+
				"signing virtual packet: %w", err)
		}

		if len(signed) != 1 || signed[0] != 0 {
			return lnwallet.AuxSigJobResp{}, fmt.Errorf("error " +
				"signing virtual packet, got no sig")
		}

		rawSig := vPacket.Outputs[0].Asset.Witnesses()[0].TxWitness[0]
		if signDesc.HashType != txscript.SigHashDefault {
			rawSig = rawSig[0:64]
		}

		sig, err := lnwire.NewSigFromSchnorrRawSignature(rawSig)
		if err != nil {
			return lnwallet.AuxSigJobResp{}, fmt.Errorf("error "+
				"converting raw sig to Schnorr: %w", err)
		}

		sigs = append(sigs, cmsg.NewAssetSig(
			vIn.PrevID.ID, sig, signDesc.HashType,
		))
	}

	htlcSigRec := &cmsg.AssetSigListRecord{
		Sigs: sigs,
	}

	return lnwallet.AuxSigJobResp{
		SigBlob:   lfn.Some(htlcSigRec.Bytes()),
		HtlcIndex: baseJob.HTLC.HtlcIndex,
	}, nil
}

// htlcSecondLevelPacketsFromCommit generates the HTLC second level packets from
// the commitment transaction. A bool is returned indicating if the HTLC was
// incoming or outgoing.
func htlcSecondLevelPacketsFromCommit(chainParams *address.ChainParams,
	chanState lnwallet.AuxChanState, commitTx *wire.MsgTx,
	keyRing lnwallet.CommitmentKeyRing, htlcOutputs []*cmsg.AssetOutput,
	baseJob lnwallet.BaseAuxJob, htlcTimeout fn.Option[uint32],
	htlcIndex uint64) ([]*tappsbt.VPacket, error) {

	packets, _, err := CreateSecondLevelHtlcPackets(
		chanState, commitTx, baseJob.HTLC.Amount.ToSatoshis(),
		keyRing, chainParams, htlcOutputs, htlcTimeout, htlcIndex,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating second level HTLC "+
			"packets: %w", err)
	}

	return packets, nil
}

// schnorrSigValidator validates a single Schnorr signature against the given
// public key.
type schnorrSigValidator struct {
	pubKey btcec.PublicKey

	tapLeaf lfn.Option[txscript.TapLeaf]

	signMethod input.SignMethod
}

// ValidateWitnesses validates the generated witnesses of an asset transfer.
// This method explicitly expects a single signature to be present in the
// witness of each input, which must be valid for the state transition and the
// given public key. But the witness as a whole is not expected to be valid yet,
// as this might represent only a single signature of a multisig output. So the
// method name might be misleading, as the full witness is _not_ validated. But
// the interface we implement requires this method signature.
func (v *schnorrSigValidator) ValidateWitnesses(newAsset *asset.Asset,
	_ []*commitment.SplitAsset, prevAssets commitment.InputSet) error {

	// Now that we know we're not dealing with a genesis state
	// transition, we'll map our set of asset inputs and outputs to
	// the 1-input 1-output virtual transaction.
	virtualTx, _, err := tapscript.VirtualTx(newAsset, prevAssets)
	if err != nil {
		return err
	}

	for idx := range newAsset.PrevWitnesses {
		witness := newAsset.PrevWitnesses[idx]
		prevAsset, ok := prevAssets[*witness.PrevID]
		if !ok {
			return fmt.Errorf("%w: no prev asset for "+
				"input_prev_id=%v", vm.ErrNoInputs,
				limitSpewer.Sdump(witness.PrevID))
		}

		var (
			sigHashType = txscript.SigHashDefault
			sigBytes    []byte
		)
		switch {
		case len(witness.TxWitness[0]) == 64:
			sigBytes = witness.TxWitness[0]

		case len(witness.TxWitness[0]) == 65:
			sigBytes = witness.TxWitness[0][:64]
			sigHashType = txscript.SigHashType(
				witness.TxWitness[0][64],
			)

		default:
			return fmt.Errorf("invalid signature length: len=%d",
				len(witness.TxWitness[0]))
		}

		schnorrSig, err := lnwire.NewSigFromSchnorrRawSignature(
			sigBytes,
		)
		if err != nil {
			return err
		}

		return v.validateSchnorrSig(
			virtualTx, prevAsset, newAsset, uint32(idx),
			sigHashType, schnorrSig,
		)
	}

	return nil
}

// validateSchnorrSig validates the given Schnorr signature against the public
// key of the validator and the sigHash of the asset transition.
func (v *schnorrSigValidator) validateSchnorrSig(virtualTx *wire.MsgTx,
	prevAsset, newAsset *asset.Asset, idx uint32,
	sigHashType txscript.SigHashType, sig lnwire.Sig) error {

	prevOutFetcher, err := tapscript.InputPrevOutFetcher(*prevAsset)
	if err != nil {
		return err
	}

	// Update the virtual transaction input with details for the specific
	// Taproot Asset input and proceed to validate its witness.
	virtualTxCopy := asset.VirtualTxWithInput(
		virtualTx, newAsset.LockTime, newAsset.RelativeLockTime, idx,
		nil,
	)

	sigHashes := txscript.NewTxSigHashes(virtualTxCopy, prevOutFetcher)

	var sigHash []byte
	switch v.signMethod {
	case input.TaprootKeySpendBIP0086SignMethod,
		input.TaprootKeySpendSignMethod:

		sigHash, err = txscript.CalcTaprootSignatureHash(
			sigHashes, sigHashType, virtualTxCopy, 0,
			prevOutFetcher,
		)
		if err != nil {
			return err
		}

	case input.TaprootScriptSpendSignMethod:
		mustLeaf := fmt.Errorf("must provide tapleaf for script spend")
		tapLeaf, err := v.tapLeaf.UnwrapOrErr(mustLeaf)
		if err != nil {
			return err
		}

		sigHash, err = txscript.CalcTapscriptSignaturehash(
			sigHashes, sigHashType, virtualTxCopy, 0,
			prevOutFetcher, tapLeaf,
		)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown sign method: %v", v.signMethod)
	}

	signature, err := sig.ToSignature()
	if err != nil {
		return err
	}

	if !signature.Verify(sigHash, &v.pubKey) {
		return fmt.Errorf("signature verification failed for sig %x, "+
			"sighash: %x and public key %x", sig.RawBytes(),
			sigHash, v.pubKey.SerializeCompressed())
	}

	return nil
}

// ScriptKeyTweakFromHtlcIndex converts the given HTLC index into a modulo N
// scalar that can be used to tweak the internal key of the HTLC script key on
// the asset level. The value of 1 is always added to the index to make sure
// this value is always non-zero.
func ScriptKeyTweakFromHtlcIndex(index input.HtlcIndex) *secp256k1.ModNScalar {
	// If we're at math.MaxUint64, we'd wrap around to 0 if we incremented
	// by 1, but we need to make sure the tweak is 1 to not cause a
	// multiplication by zero. This should never happen, as it would mean we
	// have more than math.MaxUint64 updates in a channel, which exceeds the
	// protocol's maximum.
	if index == math.MaxUint64 {
		return new(secp256k1.ModNScalar).SetInt(1)
	}

	// We need to avoid the tweak being zero, so we always add 1 to the
	// index. Otherwise, we'd multiply G by zero.
	index++

	indexAsBytes := new(big.Int).SetUint64(index).Bytes()
	indexAsScalar := new(secp256k1.ModNScalar)
	_ = indexAsScalar.SetByteSlice(indexAsBytes)

	return indexAsScalar
}

// TweakPubKeyWithIndex tweaks the given internal public key with the given
// HTLC index. The tweak is derived from the index in a way that never results
// in a zero tweak. The value of 1 is always added to the index to make sure
// this value is always non-zero. The public key is tweaked like this:
//
//	tweakedKey = key + (index+1) * G
func TweakPubKeyWithIndex(pubKey *btcec.PublicKey,
	index input.HtlcIndex) *btcec.PublicKey {

	// Avoid panic if input is nil.
	if pubKey == nil {
		return nil
	}

	// We need to operate on Jacobian points, which is just a different
	// representation of the public key that allows us to do scalar
	// multiplication.
	var (
		pubKeyJacobian, tweakTimesG, tweakedKey btcec.JacobianPoint
	)
	pubKey.AsJacobian(&pubKeyJacobian)

	// Derive the tweak from the HTLC index in a way that never results in
	// a zero tweak. Then we multiply G by the tweak.
	tweak := ScriptKeyTweakFromHtlcIndex(index)
	secp256k1.ScalarBaseMultNonConst(tweak, &tweakTimesG)

	// And finally we add the result to the key to get the tweaked key.
	secp256k1.AddNonConst(&pubKeyJacobian, &tweakTimesG, &tweakedKey)

	// Convert the tweaked key back to an affine point and create a new
	// taproot key from it.
	tweakedKey.ToAffine()
	return btcec.NewPublicKey(&tweakedKey.X, &tweakedKey.Y)
}

// TweakHtlcTree tweaks the internal key of the given HTLC script tree with the
// given index, then returns the tweaked tree with the updated taproot key.
// The tapscript tree and tapscript root are not modified.
// The internal key is tweaked like this:
//
//	tweakedInternalKey = internalKey + (index+1) * G
func TweakHtlcTree(tree input.ScriptTree,
	index input.HtlcIndex) input.ScriptTree {

	// The tapscript tree and root are not modified, only the internal key
	// is tweaked, which inherently modifies the taproot key.
	tweakedInternalPubKey := TweakPubKeyWithIndex(tree.InternalKey, index)
	newTaprootKey := txscript.ComputeTaprootOutputKey(
		tweakedInternalPubKey, tree.TapscriptRoot,
	)

	return input.ScriptTree{
		InternalKey:   tweakedInternalPubKey,
		TaprootKey:    newTaprootKey,
		TapscriptTree: tree.TapscriptTree,
		TapscriptRoot: tree.TapscriptRoot,
	}
}

// AddTweakWithIndex adds the given index to the given tweak. If the tweak is
// empty, the index is used as the tweak directly. The value of 1 is always
// added to the index to make sure this value is always non-zero.
func AddTweakWithIndex(maybeTweak []byte, index input.HtlcIndex) []byte {
	indexTweak := ScriptKeyTweakFromHtlcIndex(index)

	// If we don't already have a tweak, we just use the index as the tweak.
	if len(maybeTweak) == 0 {
		return fn.ByteSlice(indexTweak.Bytes())
	}

	// If we have a tweak, we need to parse/decode it as a scalar, then add
	// the index as a scalar, and encode it back to a byte slice.
	tweak := new(secp256k1.ModNScalar)
	_ = tweak.SetByteSlice(maybeTweak)
	newTweak := tweak.Add(indexTweak)

	return fn.ByteSlice(newTweak.Bytes())
}
