package tappsbt

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestAssetSpecifier tests the AssetSpecifier method of the VPacket struct.
func TestAssetSpecifier(t *testing.T) {
	groupPubKey := test.RandPubKey(t)
	groupKey := &asset.GroupKey{
		GroupPubKey: *groupPubKey,
	}

	tests := []struct {
		name      string
		vPacket   *VPacket
		expectErr bool
		expected  asset.Specifier
	}{
		{
			name: "valid input with group key",
			vPacket: &VPacket{
				Inputs: []*VInput{
					{
						asset: &asset.Asset{
							GroupKey: groupKey,
						},
						PrevID: asset.PrevID{
							ID: asset.ID{1, 2, 3},
						},
					},
				},
			},
			expected: asset.NewSpecifierOptionalGroupPubKey(
				asset.ID{1, 2, 3}, groupPubKey,
			),
		},
		{
			name: "valid input with asset ID only",
			vPacket: &VPacket{
				Inputs: []*VInput{
					{
						asset: &asset.Asset{},
						PrevID: asset.PrevID{
							ID: asset.ID{1, 2, 3},
						},
					},
				},
			},
			expected: asset.NewSpecifierFromId(asset.ID{1, 2, 3}),
		},
		{
			name:      "no inputs",
			vPacket:   &VPacket{},
			expectErr: true,
		},
		{
			name: "no asset set for input",
			vPacket: &VPacket{
				Inputs: []*VInput{
					{},
				},
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			specifier, err := tc.vPacket.AssetSpecifier()
			if tc.expectErr {
				require.Error(tt, err)
			} else {
				require.NoError(tt, err)
				require.Equal(tt, tc.expected, specifier)
			}
		})
	}
}
