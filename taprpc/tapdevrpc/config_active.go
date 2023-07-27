//go:build dev

package tapdevrpc

import "google.golang.org/grpc"

func RegisterGrpcServer(grpcServer *grpc.Server, srv TapDevServer) {
	RegisterTapDevServer(grpcServer, srv)
}
