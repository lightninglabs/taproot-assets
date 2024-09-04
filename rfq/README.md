# RFQ

This package contains most code related to the business logic of the Request
For Quotes subsystem.

The high-level/conceptual explanation of [how RFQ (and related concepts such
as the decimal display value and price oracles) works, can be found
in this separate document](../docs/rfq-and-decimal-display.md).

The implementation of the [RFQ fixed point arithmetic can be found in the 
`rfqmath` package](../rfqmath).

The actual [wire messages are located in the `rfqmsg`](../rfqmsg) package.

The [gRPC definitions of the RFQ methods can be found in the `taprpc/rfqrpc`
package](../taprpc/rfqrpc).

The [gRPC definitions of the price oracle methods can be found in the
`taprpc/priceoraclerpc` package](../taprpc/priceoraclerpc).

[An example implementation of a price oracle server implementing that RPC
interface with Golang can be found in
`docs/examples/basic-price-oracle`](../docs/examples/basic-price-oracle).
