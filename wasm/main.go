package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/lightninglabs/taproot-assets/taprpc/testrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func main() {
	ctx := context.Background()

	listener := bufconn.Listen(1024)
	s := &testrpc.Server{}

	rpcServer := grpc.NewServer()
	testrpc.RegisterTestServer(rpcServer, s)

	go func() {
		err := rpcServer.Serve(listener)
		if err != nil {
			panic(err)
		}
	}()

	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(
		func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		},
	), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}

	registry := make(map[string]func(context.Context, *grpc.ClientConn, string, func(string, error)))
	testrpc.RegisterTestJSONCallbacks(registry)

	fn := os.Args[0]
	params := os.Args[1]
	done := make(chan struct{})
	registry[fn](ctx, conn, params, func(resp string, err error) {
		fmt.Printf("Response: %v\n", resp)
		close(done)
	})

	<-done
}
