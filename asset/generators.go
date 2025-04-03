package asset

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
	"pgregory.net/rapid"
)

const (
	// MaxPrevWitnesses is the maximum number of PrevWitness objects
	// that will be generated when generating []Witness.
	MaxPrevWitnesses = 8

	// MaxTxWitnessElementCount is the maximum number of elements in a
	MaxTxWitnessElementCount = 64

	// MaxTxWitnessElementSize is the maximum size of a single object in a
	// generated witness stack.
	MaxTxWitnessElementSize = 64
)

var (
	// Simple generators.

	VersionGen = rapid.SampledFrom([]Version{V0, V1})

	// This is used for fields that are uint64, but clamped to UINT32_MAX
	// by other checks at runtime.
	NonZeroUint32Gen  = rapid.Uint64Range(1, math.MaxUint32)
	HashBytesGen      = NewByteSliceGen(sha256.Size)
	WitnessElementGen = rapid.SliceOfN(
		rapid.Byte(), 1, MaxTxWitnessElementSize,
	)
	AssetIDGen = rapid.Custom(func(t *rapid.T) ID {
		return (ID)(HashBytesGen.Draw(t, "asset_id"))
	})
	OutPointGen = rapid.Make[wire.OutPoint]()

	// Generators for various types of keys.

	PrivKeyGen = rapid.Custom(PrivKeyInnerGen)
	PubKeyGen  = rapid.Custom(func(t *rapid.T) *btcec.PublicKey {
		return PrivKeyGen.Draw(t, "privkey").PubKey()
	})
	MaybePubKeyGen = rapid.OneOf(
		PubKeyGen, rapid.Just[*btcec.PublicKey](nil),
	)
	KeyLocGen = rapid.Custom(func(t *rapid.T) keychain.KeyLocator {
		keyFam := rapid.Uint32().Draw(t, "key_family")

		return keychain.KeyLocator{
			Family: keychain.KeyFamily(keyFam),
			Index:  rapid.Uint32().Draw(t, "key_index"),
		}
	})
	KeyDescGen = rapid.Custom(func(t *rapid.T) keychain.KeyDescriptor {
		return keychain.KeyDescriptor{
			KeyLocator: KeyLocGen.Draw(t, "key_locator"),
			PubKey:     MaybePubKeyGen.Draw(t, "pubkey"),
		}
	})
	TweakedScriptKeyGen = rapid.Custom(func(t *rapid.T) TweakedScriptKey {
		return TweakedScriptKey{
			RawKey: KeyDescGen.Draw(t, "raw_key"),
			Tweak:  HashBytesGen.Draw(t, "tweak"),
			Type: ScriptKeyType(
				rapid.Int16().Draw(t, "script_key_type"),
			),
		}
	})
	ScriptKeyGen = rapid.Custom(func(t *rapid.T) ScriptKey {
		return ScriptKey{
			PubKey: MaybePubKeyGen.Draw(t, "pubkey"),
			TweakedScriptKey: rapid.Ptr(
				TweakedScriptKeyGen, true,
			).Draw(t, "tweaked_script_key"),
		}
	})
	SerializedKeyGen = rapid.Custom(func(t *rapid.T) SerializedKey {
		key := PubKeyGen.Draw(t, "serialized_key")
		return ToSerialized(key)
	})

	// Generators for nested structs.

	// All TxWitness will have at least 1 element of 1 byte, or be nil. This
	// helps us avoid failed equality checks for []byte{} and nil.
	TxWitnessGen = rapid.Custom(func(t *rapid.T) wire.TxWitness {
		witness := rapid.SliceOfN(
			WitnessElementGen, 1, MaxTxWitnessElementCount,
		).Draw(t, "tx_witness_non_empty")

		// We don't use rapid.Ptr here since [][]byte is already a
		// pointer type.
		return rapid.SampledFrom(
			[]wire.TxWitness{witness, nil},
		).Draw(t, "tx_witness")
	})
	NonGenesisPrevIDGen = rapid.Custom(func(t *rapid.T) PrevID {
		return PrevID{
			OutPoint:  OutPointGen.Draw(t, "outpoint"),
			ID:        AssetIDGen.Draw(t, "asset_id"),
			ScriptKey: SerializedKeyGen.Draw(t, "script_key"),
		}
	})
	GenesisGen = rapid.Custom(func(t *rapid.T) Genesis {
		return Genesis{
			FirstPrevOut: OutPointGen.Draw(t, "first_prev_out"),
			Tag: rapid.StringN(
				-1, -1, MaxAssetNameLength,
			).Draw(t, "tag"),
			MetaHash: rapid.Make[[32]byte]().Draw(
				t, "meta_hash",
			),
			OutputIndex: rapid.Uint32().Draw(t, "output_index"),
			Type: Type(rapid.IntRange(0, 1).Draw(
				t, "asset_type"),
			),
		}
	})
	SplitRootGen = rapid.Custom(func(t *rapid.T) mssmt.BranchNode {
		return *mssmt.NewComputedBranch(
			mssmt.NodeHash(HashBytesGen.Draw(t, "split_root_hash")),
			NonZeroUint32Gen.Draw(t, "split_root_sum"),
		)
	})
	WitnessGen = rapid.Custom(func(t *rapid.T) Witness {
		randomPrevID := NonGenesisPrevIDGen.Draw(t, "prev_id")
		// Add the Genesis PrevID as an explicit possibility.
		prevID := rapid.SampledFrom(
			[]*PrevID{&randomPrevID, {}},
		)

		return Witness{
			PrevID:    prevID.Draw(t, "witness prevID"),
			TxWitness: TxWitnessGen.Draw(t, "tx_witness"),
			// TODO(jhb): Implement generator for split commitments
			SplitCommitment: nil,
		}
	})
	PrevWitnessGen = rapid.SliceOfN(WitnessGen, 0, MaxPrevWitnesses)
	AssetGen       = rapid.Custom(AssetInnerGen)
)

// ByteReader is a wrapper around rapid.T that allows us to use generated random
// bytes as input for helper functions that require an io.Reader an not []byte.
type ByteReader struct {
	t        *rapid.T
	fullRead bool
	name     string
}

// NewRapidByteReader returns a new ByteReader ready for use.
func NewRapidByteReader(t *rapid.T, name string, fullRead bool) *ByteReader {
	return &ByteReader{
		t:        t,
		fullRead: fullRead,
		name:     name,
	}
}

// NewByteSliceGen constructs a generator for []byte that will always create
// fully populated slices of length p.
func NewByteSliceGen(p int) *rapid.Generator[[]byte] {
	return rapid.SliceOfN(rapid.Byte(), p, p)
}

// Read implements io.Reader. If fullRead is false for the ByteReader, output
// of size less than len(p) may be returned.
func (b *ByteReader) Read(p []byte) (n int, err error) {
	if b.t == nil {
		return 0, fmt.Errorf("byte reader not initialized")
	}

	var byteGen *rapid.Generator[[]byte]
	switch b.fullRead {
	case true:
		byteGen = NewByteSliceGen(len(p))
	case false:
		byteGen = rapid.SliceOfN(rapid.Byte(), 0, len(p))
	}

	copy(p, byteGen.Draw(b.t, b.name))
	return len(p), nil
}

// PrivKeyInnerGen generates a valid, random secp256k1 private key for use in
// property tests.
func PrivKeyInnerGen(t *rapid.T) *btcec.PrivateKey {
	randReader := NewRapidByteReader(t, "privkey", true)

	// Key generation should always succeed on the first run; our reader is
	// infallible.
	privKey, err := secp256k1.GeneratePrivateKeyFromRand(randReader)
	if err != nil {
		t.Errorf("Private key generation failed: %v", err)
	}

	return privKey
}

// AssetGenWithValues generates an Asset with some specific fields set.
func AssetGenWithValues(t *rapid.T, genesis Genesis, groupKey *GroupKey,
	scriptKey ScriptKey) *Asset {

	units := NonZeroUint32Gen.Draw(t, "units")
	switch genesis.Type {
	case Normal:

	case Collectible:
		units = 1

	default:
		t.Errorf("unhandled asset type: %v", genesis.Type)
	}

	version := VersionGen.Draw(t, "asset_version")
	locktime := rapid.Uint32().Draw(t, "locktime")
	relocktime := rapid.Uint32().Draw(t, "relocktime")
	prevWitness := PrevWitnessGen.Draw(t, "prev_witness")

	return &Asset{
		Version:             version,
		Genesis:             genesis,
		Amount:              units,
		LockTime:            uint64(locktime),
		RelativeLockTime:    uint64(relocktime),
		PrevWitnesses:       prevWitness,
		SplitCommitmentRoot: nil,
		ScriptVersion:       ScriptV0,
		ScriptKey:           scriptKey,
		GroupKey:            groupKey,
	}
}

// AssetInnerGen generates an Asset with random fields, that may also have a
// valid group key.
func AssetInnerGen(t *rapid.T) Asset {
	genesis := GenesisGen.Draw(t, "genesis")
	scriptKey := ScriptKeyGen.Draw(t, "script_key")
	protoAsset := AssetGenWithValues(t, genesis, nil, scriptKey)

	hasGroupKey := rapid.Bool().Draw(t, "has_group_key")
	if hasGroupKey {
		// Make the asset a genesis asset before creating the group key.
		protoAsset.PrevWitnesses = []Witness{{
			PrevID:          &PrevID{},
			TxWitness:       nil,
			SplitCommitment: nil,
		}}
		groupPriv := PrivKeyGen.Draw(t, "group_key_priv")
		groupKey, _ := RandGroupKeyWithSigner(
			t, groupPriv, genesis, protoAsset,
		)

		// Set the group key and group witness.
		protoAsset.GroupKey = groupKey
		protoAsset.PrevWitnesses[0].TxWitness = groupKey.Witness
	}

	return *protoAsset
}

// AltLeafGen generates an Asset with mostly random fields. The generators for
// specific fields choose between a random value and a known valid value for an
// Asset that would be an AltLeaf.
func AltLeafGen(t *rapid.T) *rapid.Generator[Asset] {
	// Generate a group key without checking for validity.
	groupKeyGen := rapid.Custom(func(t *rapid.T) GroupKey {
		return GroupKey{
			RawKey:        KeyDescGen.Draw(t, "key_desc"),
			GroupPubKey:   *PubKeyGen.Draw(t, "group_pub_key"),
			TapscriptRoot: HashBytesGen.Draw(t, "tapscript_root"),
			Witness:       TxWitnessGen.Draw(t, "witness"),
		}
	})
	maybeGroupKeyGen := rapid.Ptr(groupKeyGen, true)

	// Select between a random value and the known valid value.
	geneses := []Genesis{GenesisGen.Draw(t, "genesis"), EmptyGenesis}
	gen := rapid.SampledFrom(geneses)

	Uint64Gen := rapid.OneOf(
		rapid.Just(uint64(0)), rapid.Uint64Range(0, math.MaxUint32),
	)

	unknownOddType := tlv.TypeMap{
		test.TestVectorAllowedUnknownType: []byte("the great unknown"),
	}
	unknownOddGen := rapid.SampledFrom([]tlv.TypeMap{unknownOddType, nil})
	scriptVersGen := rapid.Custom(func(t *rapid.T) ScriptVersion {
		return ScriptVersion(rapid.Uint16().Draw(t, "script_version"))
	})

	return rapid.Custom(func(t *rapid.T) Asset {
		newLeaf := Asset{
			Version:          VersionGen.Draw(t, "version"),
			Genesis:          gen.Draw(t, "genesis"),
			Amount:           Uint64Gen.Draw(t, "amt"),
			LockTime:         Uint64Gen.Draw(t, "locktime"),
			RelativeLockTime: Uint64Gen.Draw(t, "rel_locktime"),
			PrevWitnesses: PrevWitnessGen.Draw(
				t, "prev_witness",
			),
			ScriptVersion: scriptVersGen.Draw(t, "script_version"),
			ScriptKey:     ScriptKeyGen.Draw(t, "script_key"),
			GroupKey:      maybeGroupKeyGen.Draw(t, "group_key"),
			UnknownOddTypes: unknownOddGen.Draw(
				t, "unknown_odd_types",
			),
		}

		// Handle the SplitCommitmentRoot separately, as it's an
		// interface, so rapid.Ptr() does not work.
		if rapid.Bool().Draw(t, "has_split_root") {
			splitRoot := SplitRootGen.Draw(t, "split_root")
			newLeaf.SplitCommitmentRoot = &splitRoot
		}

		return newLeaf
	})
}

// Ensure ByteReader implements the io.Reader interface.
var _ io.Reader = (*ByteReader)(nil)
