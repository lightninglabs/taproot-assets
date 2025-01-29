package tapdb

import (
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

// parseAssetMetaReveal parses the asset meta reveal from the given asset meta
// record. It will return None if the metadata hash is empty, which would be
// the case if there is no database entry for the asset meta and there was a
// LEFT JOIN in a query. Non-existence of a standalone asset metadata record
// should be decided by the sql.ErrNoRows instead.
func parseAssetMetaReveal(meta sqlc.AssetsMetum) fn.Option[proof.MetaReveal] {
	if len(meta.MetaDataHash) == 0 {
		return fn.None[proof.MetaReveal]()
	}

	return fn.Some(proof.MetaReveal{
		Data: meta.MetaDataBlob,
		Type: proof.MetaType(meta.MetaDataType.Int16),
	})
}
