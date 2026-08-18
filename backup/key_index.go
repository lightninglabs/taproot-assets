package backup

import (
	"context"
	"fmt"

	"github.com/lightningnetwork/lnd/keychain"
)

// advanceKeyFamilyIndexes advances each local LND key family through the
// highest locator represented in a wallet backup. Explicit markers cover all
// keys consumed before export, including keys for assets that were later
// spent. Asset locators provide a backward-compatible fallback for backups
// created before markers were added.
func advanceKeyFamilyIndexes(ctx context.Context, wallet *WalletBackup,
	keyRing KeyRing) error {

	highest := make(map[keychain.KeyFamily]keychain.KeyDescriptor)

	// Explicit markers only apply when the backup belongs to this LND seed.
	// Backups can also be imported on watch-only or inspection nodes, so a
	// marker from another seed is ignored instead of rejecting the assets.
	for i, marker := range wallet.KeyFamilyMarkers {
		if marker == nil || marker.PubKey == nil ||
			marker.KeyLocator.IsEmpty() {

			return fmt.Errorf("key family marker %d is "+
				"incomplete", i)
		}

		desc := keychain.KeyDescriptor{
			PubKey:     marker.PubKey,
			KeyLocator: marker.KeyLocator,
		}
		if !keyRing.IsLocalKey(ctx, desc) {
			log.Warnf("Ignoring key family marker %d "+
				"(family=%d, index=%d): marker does not "+
				"belong to the connected LND wallet", i,
				desc.Family, desc.Index)
			continue
		}

		addHighestKey(highest, desc)
	}

	// Older backups do not contain explicit markers. Their local active
	// asset locators still let us advance through the highest known key.
	for _, assetBackup := range wallet.Assets {
		if assetBackup == nil {
			continue
		}

		if info := assetBackup.ScriptKeyInfo; info != nil &&
			info.RawKey.PubKey != nil &&
			!info.RawKey.KeyLocator.IsEmpty() &&
			keyRing.IsLocalKey(ctx, info.RawKey) {

			addHighestKey(highest, info.RawKey)
		}

		if info := assetBackup.AnchorInternalKeyInfo; info != nil &&
			info.PubKey != nil && !info.KeyLocator.IsEmpty() {

			desc := keychain.KeyDescriptor{
				PubKey:     info.PubKey,
				KeyLocator: info.KeyLocator,
			}
			if keyRing.IsLocalKey(ctx, desc) {
				addHighestKey(highest, desc)
			}
		}
	}

	for family, marker := range highest {
		// Storing a key records every key in the family that precedes
		// it, so this single call advances LND's counter through the
		// marker. LND keeps the operation monotonic, never rewinds a
		// family, and bounds the number of keys it derives, so a marker
		// that is already covered is a no-op and an unreasonable marker
		// is rejected instead of causing excessive derivation.
		_, err := keyRing.DeriveAndStoreKey(ctx, marker.KeyLocator)
		if err != nil {
			return fmt.Errorf("advance key family %d through "+
				"index %d: %w", family, marker.Index, err)
		}

		log.Infof("Advanced LND key family %d through index %d",
			family, marker.Index)
	}

	return nil
}

// addHighestKey records the descriptor with the highest index per family.
func addHighestKey(highest map[keychain.KeyFamily]keychain.KeyDescriptor,
	desc keychain.KeyDescriptor) {

	current, ok := highest[desc.Family]
	if !ok || desc.Index > current.Index {
		highest[desc.Family] = desc
	}
}
