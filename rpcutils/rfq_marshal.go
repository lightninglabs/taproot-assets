package rpcutils

import (
	"fmt"
	"math/big"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
)

// UnmarshalRfqFixedPoint converts an RPC FixedPoint to a BigIntFixedPoint.
func UnmarshalRfqFixedPoint(fp *rfqrpc.FixedPoint) (*rfqmath.BigIntFixedPoint,
	error) {

	// Return an error is the scale component of the fixed point is greater
	// than the max value of uint8.
	if fp.Scale > 255 {
		return nil, fmt.Errorf("scale value overflow: %v", fp.Scale)
	}
	scale := uint8(fp.Scale)

	cBigInt := new(big.Int)
	cBigInt.SetString(fp.Coefficient, 10)

	return &rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.NewBigInt(cBigInt),
		Scale:       scale,
	}, nil
}
