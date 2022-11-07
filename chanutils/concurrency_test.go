package chanutils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrGroup(t *testing.T) {
	errs := []error{errors.New("error #1"), errors.New("error #2")}

	t.Parallel()

	returnErrFunc := func(returnErr error) error {
		if returnErr != nil {
			return returnErr
		}
		return nil
	}

	tests := []struct {
		name           string
		values         []error
		excpetedErrors []error
	}{
		{
			name:           "no errors",
			values:         []error{nil, nil},
			excpetedErrors: []error{nil},
		},
		{
			name:           "only first error",
			values:         []error{nil, errs[0]},
			excpetedErrors: []error{errs[0]},
		},
		{
			name:           "only second error",
			values:         []error{errs[1], nil},
			excpetedErrors: []error{errs[1]},
		},
		{
			name:           "any error",
			values:         []error{errs[1], errs[0]},
			excpetedErrors: []error{errs[0], errs[1]},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := ErrGroup(returnErrFunc, test.values)
			require.Contains(t, test.excpetedErrors, e)
		})
	}
}
