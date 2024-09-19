package rfqmsg

import (
	"encoding/binary"
	"testing"

	"github.com/lightningnetwork/lnd/aliasmgr"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

func intToID(scid uint64) ID {
	var id ID
	binary.BigEndian.PutUint64(id[24:], scid)
	return id
}

func shortChannelIDToID(scid lnwire.ShortChannelID) ID {
	return intToID(scid.ToUint64())
}

// TestIDSerializedScid tests that an RFQ ID can be correctly converted into a
// custom SCID alias that lies within the valid SCID block height range.
func TestIDSerializedScid(t *testing.T) {
	tests := []struct {
		id       ID
		expected lnwire.ShortChannelID
	}{
		{
			id: intToID(123456),
			expected: lnwire.ShortChannelID{
				BlockHeight: 16200181,
				TxIndex:     1,
				TxPosition:  57920,
			},
		},
		{
			id: intToID(0),
			expected: lnwire.ShortChannelID{
				BlockHeight: 16200181,
			},
		},
		{
			id: shortChannelIDToID(lnwire.ShortChannelID{
				BlockHeight: uint32(
					aliasmgr.AliasStartBlockHeight,
				),
			}),
			expected: lnwire.ShortChannelID{
				BlockHeight: uint32(
					aliasmgr.AliasStartBlockHeight,
				),
			},
		},
		{
			id: intToID(1),
			expected: lnwire.ShortChannelID{
				BlockHeight: 16200181,
				TxPosition:  1,
			},
		},
		{
			id: intToID(123456789),
			expected: lnwire.ShortChannelID{
				BlockHeight: 16200181,
				TxIndex:     1883,
				TxPosition:  52501,
			},
		},
		{
			id: shortChannelIDToID(lnwire.ShortChannelID{
				BlockHeight: uint32(
					aliasmgr.AliasEndBlockHeight + 1,
				),
				TxIndex:    123,
				TxPosition: 123,
			}),
			expected: lnwire.ShortChannelID{
				BlockHeight: uint32(
					aliasmgr.AliasStartBlockHeight,
				),
				TxIndex:    123,
				TxPosition: 123,
			},
		},
		{
			id: shortChannelIDToID(lnwire.ShortChannelID{
				BlockHeight: 10561306,
				TxIndex:     5698083,
				TxPosition:  53702,
			}),
			expected: lnwire.ShortChannelID{
				BlockHeight: 16011444,
				TxIndex:     5698083,
				TxPosition:  53702,
			},
		},
		{
			id: ID{
				0xd3, 0x62, 0x2a, 0xa3, 0x9b, 0x51, 0x53, 0x88,
				0x84, 0x2a, 0xa9, 0x78, 0x40, 0x65, 0xb3, 0x15,
				0x80, 0x56, 0xb3, 0x09, 0x80, 0xeb, 0xbb, 0x50,
				0xb8, 0xdf, 0x1a, 0x56, 0xf2, 0x23, 0xd1, 0xc6,
			},
			expected: lnwire.ShortChannelID{
				BlockHeight: 16065870,
				TxIndex:     5698083,
				TxPosition:  53702,
			},
		},
	}

	for idx, test := range tests {
		t.Logf("Running test #%d", idx)
		scid := test.id.Scid()
		shortChanID := lnwire.NewShortChanIDFromInt(uint64(scid))
		require.Equal(t, test.expected, shortChanID)

		require.GreaterOrEqual(
			t, shortChanID.BlockHeight,
			uint32(aliasmgr.AliasStartBlockHeight),
		)
		require.Less(
			t, shortChanID.BlockHeight,
			uint32(aliasmgr.AliasEndBlockHeight),
		)
		require.True(t, aliasmgr.IsAlias(shortChanID))
	}
}
