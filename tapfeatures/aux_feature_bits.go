package tapfeatures

import "github.com/lightningnetwork/lnd/lnwire"

const (
	// NoOpHTLCsRequired is a feature bit that declares the noop-htlcs as a
	// required feature.
	NoOpHTLCsRequired lnwire.FeatureBit = 0

	// NoOpHTLCsOptional is a feature bit that declares the noop-htlcs as an
	// optional feature.
	NoOpHTLCsOptional lnwire.FeatureBit = 1

	// STXORequired is a feature bit that declares STXO proofs as a required
	// feature.
	STXORequired lnwire.FeatureBit = 2

	// STXOOptional is a feature bit that declares the STXO proofs as an
	// optional feature.
	STXOOptional lnwire.FeatureBit = 3

	// NegotiatedChanCfgRequired is a feature bit that declares as required
	// that the initial (height zero) commitment of an asset channel is
	// derived from the negotiated local and remote channel configs (dust
	// limit, CSV delay). Peers without this feature derive it from zeroed
	// configs instead.
	NegotiatedChanCfgRequired lnwire.FeatureBit = 4

	// NegotiatedChanCfgOptional is a feature bit that declares as optional
	// that the initial commitment of an asset channel is derived from the
	// negotiated local and remote channel configs.
	NegotiatedChanCfgOptional lnwire.FeatureBit = 5
)

// featureNames keeps track of the string description of known features.
var featureNames = map[lnwire.FeatureBit]string{
	NoOpHTLCsRequired: "noop-htlcs",
	NoOpHTLCsOptional: "noop-htlcs",
	STXORequired:      "stxo-proofs",
	STXOOptional:      "stxo-proofs",

	NegotiatedChanCfgRequired: "negotiated-chan-cfg",
	NegotiatedChanCfgOptional: "negotiated-chan-cfg",
}

// ourFeatures returns a slice containing all of the locally supported features.
func ourFeatures() []lnwire.FeatureBit {
	// TODO(george): instead of hosting the supported features in the
	// following slice we could make something more explicit / modular.
	return []lnwire.FeatureBit{
		NoOpHTLCsOptional,
		STXOOptional,
		NegotiatedChanCfgOptional,
	}
}

// LocalFeatures returns the feature vector that we advertise to our peers.
func LocalFeatures() lnwire.FeatureVector {
	return *lnwire.NewFeatureVector(getLocalFeatureVec(), featureNames)
}

// getLocalFeatureVec returns the feature vector of the currently supported
// features. This set of features may change between different versions of tapd,
// and that exactly is its purpose. This feature vector denotes which features
// of tap channels are currently supported, in order to maintain compatibility
// with our peers.
func getLocalFeatureVec() *lnwire.RawFeatureVector {
	ourFeatures := ourFeatures()
	return lnwire.NewRawFeatureVector(
		ourFeatures...,
	)
}
