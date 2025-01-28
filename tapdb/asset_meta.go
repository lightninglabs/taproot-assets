package tapdb

import (
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

// parseAssetMetaReveal parses the asset meta reveal from the given asset meta
// record. It will return None if the metadata hash is empty, which would be
// the case if there is no database entry for the asset meta and there was a
// LEFT JOIN in a query. Non-existence of a standalone asset metadata record
// should be decided by the sql.ErrNoRows instead.
func parseAssetMetaReveal(
	meta sqlc.AssetsMetum) (fn.Option[proof.MetaReveal], error) {

	if len(meta.MetaDataHash) == 0 {
		return fn.None[proof.MetaReveal](), nil
	}

	var canonicalUniverse fn.Option[[]url.URL]
	if len(meta.MetaCanonicalUniverses) > 0 {
		urls := strings.Split(
			string(meta.MetaCanonicalUniverses), "\x00",
		)
		canonicalUniverseURLs := make([]url.URL, len(urls))
		for i, u := range urls {
			canonicalUniverseURL, err := url.ParseRequestURI(u)
			if err != nil {
				return fn.None[proof.MetaReveal](), err
			}
			canonicalUniverseURLs[i] = *canonicalUniverseURL
		}

		canonicalUniverse = fn.Some(canonicalUniverseURLs)
	}

	var delegationKey fn.Option[btcec.PublicKey]
	if len(meta.MetaDelegationKey) > 0 {
		key, err := btcec.ParsePubKey(meta.MetaDelegationKey)
		if err != nil {
			return fn.None[proof.MetaReveal](), err
		}

		delegationKey = fn.Some(*key)
	}

	return fn.Some(proof.MetaReveal{
		Data: meta.MetaDataBlob,
		Type: proof.MetaType(meta.MetaDataType.Int16),
		DecimalDisplay: extractOptSqlInt32[uint32](
			meta.MetaDecimalDisplay,
		),
		UniverseCommitments: extractBool(meta.MetaUniverseCommitments),
		CanonicalUniverses:  canonicalUniverse,
		DelegationKey:       delegationKey,
	}), nil
}
