package rfq

import (
	"fmt"
	"os"

	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"gopkg.in/macaroon.v2"
)

// NewMacaroonDialOption reads a macaroon file from disk and returns
// a gRPC DialOption that attaches it as per-RPC credentials.
func NewMacaroonDialOption(path string) (grpc.DialOption, error) {
	macBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read macaroon "+
			"path: %w", err)
	}

	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("unable to decode "+
			"macaroon: %w", err)
	}

	cred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("error creating macaroon "+
			"credential: %w", err)
	}

	return grpc.WithPerRPCCredentials(cred), nil
}
