package testrpc

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/mssmt"
)

type Server struct {
	UnimplementedTestServer
}

func (s *Server) SayHello(ctx context.Context,
	in *HelloRequest) (*HelloResponse, error) {

	store := mssmt.NewDefaultStore()
	tree := mssmt.NewFullTree(store)

	_, err := tree.Insert(
		ctx, [32]byte{1, 2, 3}, mssmt.NewLeafNode([]byte(in.Name), 123),
	)
	if err != nil {
		panic(err)
	}

	root, err := tree.Root(ctx)
	if err != nil {
		panic(err)
	}

	return &HelloResponse{
		Message: fmt.Sprintf("Hello %s, your tree root is %v", in.Name,
			root.NodeHash().String()),
	}, nil
}
