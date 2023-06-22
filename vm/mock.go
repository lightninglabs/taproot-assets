package vm

import (
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
)

type ValidTestCase struct {
	Asset    *asset.TestAsset        `json:"asset"`
	SplitSet commitment.TestSplitSet `json:"split_set"`
	InputSet commitment.TestInputSet `json:"input_set"`
	Comment  string                  `json:"comment"`
}

type ErrorTestCase struct {
	Asset    *asset.TestAsset        `json:"asset"`
	SplitSet commitment.TestSplitSet `json:"split_set"`
	InputSet commitment.TestInputSet `json:"input_set"`
	Error    string                  `json:"error"`
	Comment  string                  `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}
