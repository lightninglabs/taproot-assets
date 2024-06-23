package main

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
)

var buf [1024]byte

//go:export getBuffer
func getBuffer() *byte {
	return &buf[0]
}

//go:export hello
func hello(inputLength int32) int32 {
	ctx := context.Background()

	store := mssmt.NewDefaultStore()
	tree := mssmt.NewFullTree(store)

	fmt.Printf("Buf: %x (%s)\n", buf[:inputLength], buf[:inputLength])
	fmt.Printf("Test: %v\n", inputLength)

	_, err := tree.Insert(
		ctx, [32]byte{1, 2, 3}, mssmt.NewLeafNode(buf[:], 123),
	)
	if err != nil {
		panic(err)
	}

	root, err := tree.Root(ctx)
	if err != nil {
		panic(err)
	}

	response := fmt.Sprintf("Hello äüpöä %x", fn.ByteSlice(root.NodeHash()))
	fmt.Printf("Go response: %v\n", response)

	copy(buf[:], response)

	return int32(len(response))
}

// main is required for the `wasi` target, even if it isn't used.
func main() {}
