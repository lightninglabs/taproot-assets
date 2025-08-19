package tapfeatures

// CustomChannelType is a uint64 that hosts all the possible custom feature
// bits. These feature bits correspond to various tap-channel specific features
// and each feature resides on a specific bit position.
type CustomChannelType uint64

const (
	// NoOpHTLCsBit is the feature bit which signals that NoOp HTLCs should
	// be used over the channels.
	NoOpHTLCsBit CustomChannelType = 1 << 0

	// STXOBit is a feature bit which signals that STXO proofs must be used
	// for the channel commitments.
	STXOBit CustomChannelType = 1 << 1
)

func (c CustomChannelType) HasNoOpHTLCsBit() bool {
	return c&NoOpHTLCsBit == NoOpHTLCsBit
}

func (c CustomChannelType) HasSTXOBit() bool {
	return c&STXOBit == STXOBit
}

func getCustomChannelType() CustomChannelType {
	customChanType := NoOpHTLCsBit
	customChanType |= STXOBit

	return customChanType
}
