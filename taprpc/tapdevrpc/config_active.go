//go:build dev

package tapdevrpc

import "google.golang.org/grpc"

func RegisterGrpcServer(registrar grpc.ServiceRegistrar, srv TapDevServer) {
	RegisterTapDevServer(registrar, srv)
}
