package main

import (
	"testing"
)

// Coinbase TX, block 734621
// testUTXO := "9d9b914bfbd6935fe74dbdfe717415970d6421a02bb47609572eeaf987a1fbc3"
// TX that spends multiple coinbases, block 734246
// testUTXO := "3a28f820d19cac38669f986c9764f63288e587cfc5ef5a2273d8c1e9db7d25c1"
// Old TX 5 hops away from 2 coinbases
// f03870cc3b9e2e52ee7e84056975156d69dbb94715805f6ad5644a9588ae7026
// 63e8673e42e5c1aadf6e2ccadbbb27a1726e8cc3a1a9638bfdb93f769b186f8c
// 2689ad76a1034100eaa0e4e0672e585fb7db5e706e01615e7c20fe1132140ce7
// 88f893859ebff2f8d9b0234a7e8cfae2c83028e984415a2658a8f5a09b8c6038
// Coinbases:
// cd8da0a6b7057cf4926fb07a328d7b0e617bb99002deebe65b3ce1c9a27139db
// 0eccbafc25df83496d2844e0e345d58af5ab38e46cfe1ca1ce638fec1e680364
// testUTXO := "94c3b2681a40d97f8c4c28b5420fb8ff7dac2dcfb12c15490b3de993eecddb9b"

func TestCoinbase(t *testing.T) {
	type test struct {
		input  string
		output [][]int32
	}

	tests := map[string]test{
		"Coinbase": {
			input: "9d9b914bfbd6935fe74dbdfe717415970d6421a02bb47609572eeaf987a1fbc3",
			output: [][]int32{
				[]int32{734621},
			},
		},
		"One Hop": {
			input: "3a28f820d19cac38669f986c9764f63288e587cfc5ef5a2273d8c1e9db7d25c1",
			output: [][]int32{
				[]int32{734246, 734109},
				[]int32{734246, 733996},
				[]int32{734246, 734035},
				[]int32{734246, 734016},
				[]int32{734246, 734079},
				[]int32{734246, 734000},
				[]int32{734246, 733989},
				[]int32{734246, 734039},
				[]int32{734246, 733987},
				[]int32{734246, 734086},
				[]int32{734246, 733997},
				[]int32{734246, 734017},
				[]int32{734246, 733988},
				[]int32{734246, 734032},
				[]int32{734246, 734085},
				[]int32{734246, 734123},
				[]int32{734246, 734014},
				[]int32{734246, 734122},
				[]int32{734246, 734103},
				[]int32{734246, 734067},
				[]int32{734246, 734046},
				[]int32{734246, 733993},
				[]int32{734246, 734108},
				[]int32{734246, 733999},
				[]int32{734246, 734061},
				[]int32{734246, 734034},
				[]int32{734246, 734115},
				[]int32{734246, 734097},
				[]int32{734246, 734011},
				[]int32{734246, 733998},
			},
		},
		"Multi Hop": {
			input: "3a28f820d19cac38669f986c9764f63288e587cfc5ef5a2273d8c1e9db7d25c1",
			output: [][]int32{
				[]int32{63961, 63941, 63930, 63904, 61344, 61162},
				[]int32{63961, 63941, 63930, 63904, 61344, 61195},
			},
		},
	}

	// TODO: Finish testing loop
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
		})

	}
}
