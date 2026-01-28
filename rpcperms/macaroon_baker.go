package rpcperms

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/lightninglabs/lndclient"
	"github.com/lightningnetwork/lnd/macaroons"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon.v2"
)

// Permission is an entity/action pair that can be baked into a macaroon.
type Permission struct {
	// Entity is the permission entity to bake.
	Entity string

	// Action is the permission action to bake.
	Action string
}

// BakeRequest contains the permissions and options for a new macaroon.
type BakeRequest struct {
	// Permissions is the list of permissions for the baked macaroon.
	Permissions []Permission

	// RootKeyID is the root key identifier used for baking.
	RootKeyID uint64

	// AllowExternalPermissions allows permissions that are not in the
	// registered permission map.
	AllowExternalPermissions bool
}

// MacaroonBaker validates bake requests and mints new macaroons.
type MacaroonBaker interface {
	// BakeMacaroon creates a new macaroon with the given permissions.
	BakeMacaroon(ctx context.Context, req BakeRequest) (macaroon.Macaroon,
		error)
}

// MacBakerConfig contains the configuration for the macaroon baker.
type MacBakerConfig struct {
	// MacaroonService is the macaroon service used to mint new macaroons.
	MacaroonService *lndclient.MacaroonService

	// RequiredPermissions holds the known RPC permission map for URI
	// checks.
	RequiredPermissions map[string][]bakery.Op
}

// MacBaker is a macaroon baker implementation.
type MacBaker struct {
	// cfg contains the configuration for the macaroon baker.
	cfg MacBakerConfig

	// validEntities contains all allowed permission entities.
	validEntities map[string]struct{}

	// validActions contains all allowed permission actions.
	validActions map[string]struct{}

	// validEntityActions contains all allowed entity/action pairs.
	validEntityActions map[string]map[string]struct{}

	// helpMsg is appended to validation errors to hint valid values.
	helpMsg string
}

// NewMacaroonBaker returns a MacaroonBaker backed by tapd's macaroon service
// and permission map.
func NewMacaroonBaker(macaroonService *lndclient.MacaroonService,
	requiredPermissions map[string][]bakery.Op) MacaroonBaker {

	validEntities := make(map[string]struct{})
	validActions := make(map[string]struct{})
	validEntityActions := make(map[string]map[string]struct{})

	for _, perms := range requiredPermissions {
		for _, perm := range perms {
			validEntities[perm.Entity] = struct{}{}
			validActions[perm.Action] = struct{}{}

			entityActions, ok := validEntityActions[perm.Entity]
			if !ok {
				entityActions = make(map[string]struct{})
				validEntityActions[perm.Entity] = entityActions
			}

			entityActions[perm.Action] = struct{}{}
		}
	}

	validEntities[macaroons.PermissionEntityCustomURI] = struct{}{}

	sortedKeys := func(entries map[string]struct{}) []string {
		keys := make([]string, 0, len(entries))
		for key := range entries {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return keys
	}

	helpMsg := fmt.Sprintf("supported actions are %v, supported entities "+
		"are %v", sortedKeys(validActions), sortedKeys(validEntities))

	return &MacBaker{
		cfg: MacBakerConfig{
			MacaroonService:     macaroonService,
			RequiredPermissions: requiredPermissions,
		},
		validEntities:      validEntities,
		validActions:       validActions,
		validEntityActions: validEntityActions,
		helpMsg:            helpMsg,
	}
}

// BakeMacaroon allows the creation of a new macaroon with custom permissions.
// No first-party caveats are added since this can be done offline.
func (b *MacBaker) BakeMacaroon(ctx context.Context,
	req BakeRequest) (macaroon.Macaroon, error) {

	var zero macaroon.Macaroon

	// Don't allow empty permission list as it doesn't make sense to have
	// a macaroon that is not allowed to access any RPC.
	if len(req.Permissions) == 0 {
		return zero, fmt.Errorf("permission list cannot be empty. "+
			"specify at least one action/entity pair. %s",
			b.helpMsg)
	}

	// Validate and map permission struct used by gRPC to the one used by
	// the bakery. If the allow_external_permissions flag is set, we
	// will not validate, but map.
	requestedPermissions := make([]bakery.Op, len(req.Permissions))
	for idx, op := range req.Permissions {
		if req.AllowExternalPermissions {
			requestedPermissions[idx] = bakery.Op{
				Entity: op.Entity,
				Action: op.Action,
			}
			continue
		}

		if _, ok := b.validEntities[op.Entity]; !ok {
			return zero, fmt.Errorf("invalid permission entity. %s",
				b.helpMsg)
		}

		// Either we have the special entity "uri" which specifies a
		// full gRPC URI or we have one of the pre-defined actions.
		if op.Entity == macaroons.PermissionEntityCustomURI {
			_, ok := b.cfg.RequiredPermissions[op.Action]
			if !ok {
				return zero, fmt.Errorf("invalid permission " +
					"action, must be an existing URI in " +
					"the format /package.Service/" +
					"MethodName")
			}
		} else {
			if _, ok := b.validActions[op.Action]; !ok {
				return zero, fmt.Errorf("invalid permission "+
					"action. %s", b.helpMsg)
			}

			entityActions, ok := b.validEntityActions[op.Entity]
			if !ok {
				return zero, fmt.Errorf("unsupported "+
					"permission pair. %s", b.helpMsg)
			}
			if _, ok := entityActions[op.Action]; !ok {
				return zero, fmt.Errorf("unsupported "+
					"permission pair. %s", b.helpMsg)
			}
		}

		requestedPermissions[idx] = bakery.Op{
			Entity: op.Entity,
			Action: op.Action,
		}
	}

	// Convert root key id from uint64 to bytes. Because the
	// DefaultRootKeyID is a digit 0 expressed in a byte slice of a string
	// "0", we will keep the IDs in the same format - all must be numeric,
	// and must be a byte slice of string value of the digit, e.g.,
	// uint64(123) to string(123).
	rootKeyID := []byte(strconv.FormatUint(req.RootKeyID, 10))

	// Bake new macaroon with the given permissions and send it binary
	// serialized and hex encoded to the client.
	newMac, err := b.cfg.MacaroonService.NewMacaroon(
		ctx, rootKeyID, requestedPermissions...,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to create new macaroon: %w",
			err)
	}

	underlyingMac := newMac.M()
	return *underlyingMac, nil
}
