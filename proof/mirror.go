package proof

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
)

// The daemon keeps two copies of every proof it materializes: the
// database store, which the anchoring watcher's site handlers rewrite
// and delete inside their delivery transactions, and the flat-file
// tree, a mirror kept for disaster recovery that no transaction can
// reach. The mirror is brought back into lockstep through the
// watcher's outbox: a handler that rewrote or deleted database proofs
// enqueues a mirror-sync effect naming their locators, and the
// dispatcher below replays the change against the file tree after
// the transaction commits.

const (
	// MirrorSyncEffectKind is the outbox effect kind under which the
	// proof-file mirror is brought into lockstep with the database
	// store. It is housekeeping rather than an act-gated emission:
	// any handler that rewrites or deletes database proofs enqueues
	// it, at whatever phase.
	//
	// An untyped constant so it assigns to the watcher's effect kind
	// without this package importing the watcher.
	MirrorSyncEffectKind = "proof.mirror-sync"

	// mirrorSyncVersion versions the mirror-sync payload encoding.
	mirrorSyncVersion = 1

	// mirrorLocatorSize is the encoded size of one locator: asset ID,
	// compressed script key, outpoint hash and outpoint index.
	mirrorLocatorSize = 32 + btcec.PubKeyBytesLenCompressed + 32 + 4
)

// MirrorSyncOp names what the mirror has to replay.
type MirrorSyncOp uint8

const (
	// MirrorSyncDelete removes the mirror's file for each locator.
	MirrorSyncDelete MirrorSyncOp = 1

	// MirrorSyncRewrite rewrites the mirror's file for each locator
	// from the authoritative store.
	MirrorSyncRewrite MirrorSyncOp = 2
)

// MirrorSyncPayload is the mirror-sync effect's payload: the operation
// and the proofs it applies to. Every locator carries an asset ID, a
// script key and an outpoint — exactly what names a file in the
// mirror.
type MirrorSyncPayload struct {
	// Op is the operation to replay.
	Op MirrorSyncOp

	// Locators name the affected proofs.
	Locators []Locator
}

// Encode encodes the payload, returning its version and bytes.
func (p MirrorSyncPayload) Encode() (uint16, []byte, error) {
	switch p.Op {
	case MirrorSyncDelete, MirrorSyncRewrite:
	default:
		return 0, nil, fmt.Errorf("unknown mirror sync op %d", p.Op)
	}

	data := make([]byte, 0, 1+4+len(p.Locators)*mirrorLocatorSize)
	data = append(data, byte(p.Op))
	data = binary.BigEndian.AppendUint32(data, uint32(len(p.Locators)))

	for idx := range p.Locators {
		loc := p.Locators[idx]
		switch {
		case loc.AssetID == nil:
			return 0, nil, ErrInvalidLocatorID

		case loc.OutPoint == nil:
			return 0, nil, ErrOutPointMissing
		}

		data = append(data, loc.AssetID[:]...)
		data = append(data, loc.ScriptKey.SerializeCompressed()...)
		data = append(data, loc.OutPoint.Hash[:]...)
		data = binary.BigEndian.AppendUint32(data, loc.OutPoint.Index)
	}

	return mirrorSyncVersion, data, nil
}

// DecodeMirrorSyncPayload decodes a payload of any version ever
// written.
func DecodeMirrorSyncPayload(version uint16,
	data []byte) (MirrorSyncPayload, error) {

	var out MirrorSyncPayload
	if version != mirrorSyncVersion {
		return out, fmt.Errorf("unknown mirror sync payload "+
			"version %d", version)
	}
	if len(data) < 1+4 {
		return out, fmt.Errorf("mirror sync payload has %d bytes",
			len(data))
	}

	out.Op = MirrorSyncOp(data[0])
	switch out.Op {
	case MirrorSyncDelete, MirrorSyncRewrite:
	default:
		return out, fmt.Errorf("unknown mirror sync op %d", out.Op)
	}

	count := binary.BigEndian.Uint32(data[1:5])
	rest := data[5:]
	if uint64(len(rest)) != uint64(count)*mirrorLocatorSize {
		return out, fmt.Errorf("mirror sync payload names %d "+
			"locators in %d bytes", count, len(rest))
	}

	out.Locators = make([]Locator, 0, count)
	for len(rest) > 0 {
		var (
			assetID asset.ID
			op      wire.OutPoint
		)
		copy(assetID[:], rest[:32])
		rest = rest[32:]

		scriptKey, err := btcec.ParsePubKey(
			rest[:btcec.PubKeyBytesLenCompressed],
		)
		if err != nil {
			return out, fmt.Errorf("unable to parse script "+
				"key: %w", err)
		}
		rest = rest[btcec.PubKeyBytesLenCompressed:]

		copy(op.Hash[:], rest[:32])
		op.Index = binary.BigEndian.Uint32(rest[32:36])
		rest = rest[36:]

		out.Locators = append(out.Locators, Locator{
			AssetID:   &assetID,
			ScriptKey: *scriptKey,
			OutPoint:  &op,
		})
	}

	return out, nil
}

// MirrorSyncCfg carries the mirror-sync dispatcher's dependencies.
type MirrorSyncCfg struct {
	// Source is the authoritative store a rewrite reads from.
	Source Archiver

	// Mirror is the file tree kept in lockstep with the source.
	Mirror *FileArchiver
}

// DispatchMirrorSync is the outbox dispatch handler for the mirror-sync
// effect: it replays a database-side proof deletion or rewrite against
// the file mirror. Idempotent, so outbox redelivery is safe: a delete
// of a file already gone is a no-op, and a rewrite copies whatever the
// source currently holds — or nothing, when the source no longer holds
// the proof, since a later abandonment may have deleted it and
// enqueued the matching delete.
func DispatchMirrorSync(ctx context.Context, cfg MirrorSyncCfg,
	version uint16, data []byte) error {

	payload, err := DecodeMirrorSyncPayload(version, data)
	if err != nil {
		return err
	}

	for idx := range payload.Locators {
		loc := payload.Locators[idx]

		switch payload.Op {
		case MirrorSyncDelete:
			if err := cfg.Mirror.RemoveProof(ctx, loc); err != nil {
				return fmt.Errorf("unable to remove mirror "+
					"proof: %w", err)
			}

		case MirrorSyncRewrite:
			blob, err := cfg.Source.FetchProof(ctx, loc)
			switch {
			case errors.Is(err, ErrProofNotFound):
				continue

			case err != nil:
				return fmt.Errorf("unable to fetch source "+
					"proof: %w", err)
			}

			// The file archiver overwrites whether or not the
			// file exists, and the mirror may not hold the
			// file yet: the porter writes its own outputs'
			// files only after the confirmation that enqueued
			// this rewrite has been delivered to it.
			err = cfg.Mirror.ImportVerifiedProofs(
				ctx, false, newVerifiedAnnotatedProof(
					&AnnotatedProof{
						Locator: loc,
						Blob:    blob,
					},
				),
			)
			if err != nil {
				return fmt.Errorf("unable to rewrite mirror "+
					"proof: %w", err)
			}
		}
	}

	return nil
}
