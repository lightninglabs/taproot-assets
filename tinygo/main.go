package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
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

	assetBytes, err := hex.DecodeString("0001010265fca6685a399ad7e9088ba3911c5b2f02b07cffc319f8086e3f129fbf647c4537000000011b69746573742d61737365742d63656e74732d7472616e6368652d32811ad3c42f355c915d1fc4ba4ed71337092191431308f975d7acbc88a09ab98100000000000401000603fd138a0901040bad01ab01651145af966796fc5f4e7ec057acd24b38c5d0060bfe8e0c74e4c9464c08993a330000000017e137755dac067b0e1d91e33d077ab3482fbe1c382d424412c4620a8e3455eb02e9fa4e023746d43a7440b4148fb00f83f8b22ecb67625313fcb54442df2bdfb403420140791e35d3b49d0c1a1ec6415ba419f027fb4fcf254773e9c54ba77715a793e33c67175901e020b9ed87ab2161aa17a572def28d638ca3656fd5f27d6fd974ae280e020000102102e9fa4e023746d43a7440b4148fb00f83f8b22ecb67625313fcb54442df2bdfb4112102f37e9d09521076209768a6028aa2b42000b042a0635cb90f257c8b00c34a3688")
	if err != nil {
		panic(err)
	}

	var a asset.Asset
	err = a.Decode(bytes.NewReader(assetBytes))
	if err != nil {
		panic(err)
	}

	t := &testing.T{}
	jsonAsset := asset.NewTestFromAsset(t, &a)
	jsonAssetBytes, err := json.Marshal(jsonAsset)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Buf: %x (%s)\n", buf[:inputLength], buf[:inputLength])
	fmt.Printf("Test: %v\n", inputLength)

	_, err = tree.Insert(
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
	response += fmt.Sprintf("asset: %v", string(jsonAssetBytes))
	fmt.Printf("Go response: %v\n", response)

	copy(buf[:], response)

	return int32(len(response))
}

// main is required for the `wasi` target, even if it isn't used.
func main() {}
