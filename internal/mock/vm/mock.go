package vm

import (
	"github.com/lightninglabs/taproot-assets/json"
)

type ValidTestCase struct {
	Asset       *json.Asset   `json:"asset"`
	SplitSet    json.SplitSet `json:"split_set"`
	InputSet    json.InputSet `json:"input_set"`
	BlockHeight uint32        `json:"block_height"`
	Comment     string        `json:"comment"`
}

type ErrorTestCase struct {
	Asset       *json.Asset   `json:"asset"`
	SplitSet    json.SplitSet `json:"split_set"`
	InputSet    json.InputSet `json:"input_set"`
	BlockHeight uint32        `json:"block_height"`
	Error       string        `json:"error"`
	Comment     string        `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}
