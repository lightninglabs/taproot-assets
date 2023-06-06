package fn

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParSlice(t *testing.T) {
	t.Parallel()
	errs := []error{errors.New("error #1"), errors.New("error #2")}

	returnErrFunc := func(ctx context.Context, returnErr error) error {
		if returnErr != nil {
			return returnErr
		}
		return nil
	}

	tests := []struct {
		name           string
		values         []error
		expectedErrors []error
	}{
		{
			name:           "no errors",
			values:         []error{nil, nil},
			expectedErrors: []error{nil},
		},
		{
			name:           "only first error",
			values:         []error{nil, errs[0]},
			expectedErrors: []error{errs[0]},
		},
		{
			name:           "only second error",
			values:         []error{errs[1], nil},
			expectedErrors: []error{errs[1]},
		},
		{
			name:           "any error",
			values:         []error{errs[1], errs[0]},
			expectedErrors: []error{errs[0], errs[1]},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			e := ParSlice(
				context.TODO(), test.values, returnErrFunc,
			)
			require.Contains(t, test.expectedErrors, e)
		})
	}
}
