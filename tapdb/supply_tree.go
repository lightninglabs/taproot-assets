package tapdb

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"

	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
)

const (
	// supplyRootNS is the prefix for the root supply tree namespace.
	supplyRootNS = "supply-root"

	// supplySubTreeNS is the prefix for supply sub-tree namespaces.
	supplySubTreeNS = "supply-sub"
)
// rootSupplyNamespace generates the SMT namespace for the root supply tree
// associated with a given group key.
func rootSupplyNamespace(groupKey *btcec.PublicKey) string {
	keyHex := hex.EncodeToString(groupKey.SerializeCompressed())
	return fmt.Sprintf("%s-%s", supplyRootNS, keyHex)
}

// subTreeNamespace generates the SMT namespace for a specific supply sub-tree
// (mint, burn, ignore) associated with a given group key.
func subTreeNamespace(groupKey *btcec.PublicKey,
	treeType supplycommit.SupplySubTree) string {

	keyHex := hex.EncodeToString(groupKey.SerializeCompressed())
	return fmt.Sprintf("%s-%s-%s", supplySubTreeNS,
		treeType.String(), keyHex)
}
