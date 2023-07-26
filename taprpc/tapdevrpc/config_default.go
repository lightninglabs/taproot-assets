//go:build !dev

package tapdevrpc

import "google.golang.org/grpc"

func RegisterGrpcServer(_ *grpc.Server, _ TapDevServer) {
}
