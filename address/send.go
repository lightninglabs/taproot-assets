package address

import "github.com/lightninglabs/taproot-assets/asset"

type SendFragmentVersion uint8

type ScriptKeyDerivationMethod uint8

const (
	// ScriptKeyDerivationBip86 means the script key is derived using the
	// address's recipient ID key and an BIP-0086 taproot tweak. This can
	// only be used for packets that have a single asset ID, otherwise the
	// proofs for the packet would collide in the universe.
	ScriptKeyDerivationBip86 ScriptKeyDerivationMethod = 0

	// ScriptKeyDerivationUniqueOpReturn means the script key is derived
	// using the address's recipient ID key and a single OP_RETURN leaf that
	// contains the asset ID of the packet (OP_RETURN <asset_id>). This can
	// be used to create unique script keys for each virtual packet in the
	// fragment, to avoid proof collisions in the universe.
	ScriptKeyDerivationUniqueOpReturn ScriptKeyDerivationMethod = 1

	// ScriptKeyDerivationUniquePedersen means the script key is derived
	// using the address's recipient ID key and a single leaf that contains
	// an un-spendable Pedersen commitment key
	// (OP_CHECKSIG <NUMS_key + asset_id * G>). This can be used to
	// create unique script keys for each virtual packet in the fragment,
	// to avoid proof collisions in the universe, where the script keys
	// should be spendable by a hardware wallet that only supports
	// miniscript policies for signing P2TR outputs.
	ScriptKeyDerivationUniquePedersen ScriptKeyDerivationMethod = 2
)

type SendPacket struct {
	Amount              uint64
	ScriptKey           asset.SerializedKey
	ScriptKeyDerivation ScriptKeyDerivationMethod
}

type SendFragment struct {
	Version   SendFragmentVersion
	Specifier asset.Specifier
	Packets   map[asset.ID]SendPacket
}
