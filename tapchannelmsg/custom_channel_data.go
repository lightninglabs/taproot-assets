package tapchannelmsg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"google.golang.org/protobuf/proto"
)

// ReadOpenChannel reads the content of an OpenChannel struct from a reader.
func ReadOpenChannel(r io.Reader, maxReadSize uint32) (*OpenChannel, error) {
	openChanData, err := wire.ReadVarBytes(r, 0, maxReadSize, "chan data")
	if err != nil {
		return nil, fmt.Errorf("unable to read open chan data: %w", err)
	}

	var openChannelRecord OpenChannel
	err = openChannelRecord.Decode(bytes.NewReader(openChanData))
	if err != nil {
		return nil, fmt.Errorf("error decoding custom channel data: %w",
			err)
	}

	return &openChannelRecord, nil
}

// ReadCommitment reads the content of a Commitment struct from a reader.
func ReadCommitment(r io.Reader, maxReadSize uint32) (*Commitment, error) {
	localCommitData, err := wire.ReadVarBytes(
		r, 0, maxReadSize, "commit data",
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read open chan data: %w", err)
	}

	var localCommit Commitment
	err = localCommit.Decode(bytes.NewReader(localCommitData))
	if err != nil {
		return nil, fmt.Errorf("error decoding custom commit data: %w",
			err)
	}

	return &localCommit, nil
}

// ChannelCustomData represents the data that is returned in the
// CustomChannelData field of a lnrpc.Channel object.
type ChannelCustomData struct {
	OpenChan    OpenChannel
	LocalCommit Commitment
}

// AsJson returns the JSON representation of the channel custom data.
func (c *ChannelCustomData) AsJson() ([]byte, error) {
	if len(c.OpenChan.Assets()) == 0 {
		return []byte{}, nil
	}

	resp := &rfqmsg.JsonAssetChannel{}
	for _, output := range c.OpenChan.Assets() {
		a := output.Proof.Val.Asset

		assetID := a.ID()
		utxo := rfqmsg.JsonAssetUtxo{
			Version: int64(a.Version),
			AssetGenesis: rfqmsg.JsonAssetGenesis{
				GenesisPoint: a.FirstPrevOut.String(),
				Name:         a.Tag,
				MetaHash: hex.EncodeToString(
					a.MetaHash[:],
				),
				AssetID: hex.EncodeToString(assetID[:]),
			},
			Amount: a.Amount,
			ScriptKey: hex.EncodeToString(
				a.ScriptKey.PubKey.SerializeCompressed(),
			),
		}
		resp.Assets = append(resp.Assets, rfqmsg.JsonAssetChanInfo{
			AssetInfo:     utxo,
			Capacity:      output.Amount.Val,
			LocalBalance:  c.LocalCommit.LocalAssets.Val.Sum(),
			RemoteBalance: c.LocalCommit.RemoteAssets.Val.Sum(),
		})
	}

	return json.Marshal(resp)
}

// ReadChannelCustomData reads the content of a ChannelCustomData struct from a
// byte slice.
func ReadChannelCustomData(chanData []byte) (*ChannelCustomData, error) {
	chanDataReader := bytes.NewReader(chanData)

	// The custom channel data is encoded as two var byte blobs. One for
	// the static funding data, one for the state of our current local
	// commitment.
	openChannel, err := ReadOpenChannel(
		chanDataReader, uint32(len(chanData)),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read open channel: %w", err)
	}

	localCommit, err := ReadCommitment(
		chanDataReader, uint32(len(chanData)),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read local commitment: %w",
			err)
	}

	return &ChannelCustomData{
		OpenChan:    *openChannel,
		LocalCommit: *localCommit,
	}, nil
}

// BalanceCustomData represents the data that is returned in the
// CustomChannelData field of a lnrpc.ChannelBalanceResponse object.
type BalanceCustomData struct {
	OpenChannels    []*Commitment
	PendingChannels []*Commitment
}

// AsJson returns the JSON representation of the channel balance data.
func (b *BalanceCustomData) AsJson() ([]byte, error) {
	if len(b.OpenChannels) == 0 && len(b.PendingChannels) == 0 {
		return []byte{}, nil
	}

	resp := &rfqmsg.JsonAssetChannelBalances{
		OpenChannels:    make(map[string]*rfqmsg.JsonAssetBalance),
		PendingChannels: make(map[string]*rfqmsg.JsonAssetBalance),
	}
	for _, openChan := range b.OpenChannels {
		for _, assetOutput := range openChan.LocalOutputs() {
			assetID := assetOutput.Proof.Val.Asset.ID()

			assetIDStr := hex.EncodeToString(assetID[:])
			assetName := assetOutput.Proof.Val.Asset.Tag

			assetBalance, ok := resp.OpenChannels[assetIDStr]
			if !ok {
				assetBalance = &rfqmsg.JsonAssetBalance{
					AssetID: assetIDStr,
					Name:    assetName,
				}
				resp.OpenChannels[assetIDStr] = assetBalance
			}

			assetBalance.LocalBalance += assetOutput.Amount.Val
		}

		for _, assetOutput := range openChan.RemoteOutputs() {
			assetID := assetOutput.Proof.Val.Asset.ID()

			assetIDStr := hex.EncodeToString(assetID[:])
			assetName := assetOutput.Proof.Val.Asset.Tag

			assetBalance, ok := resp.OpenChannels[assetIDStr]
			if !ok {
				assetBalance = &rfqmsg.JsonAssetBalance{
					AssetID: assetIDStr,
					Name:    assetName,
				}
				resp.OpenChannels[assetIDStr] = assetBalance
			}

			assetBalance.RemoteBalance += assetOutput.Amount.Val
		}
	}

	for _, pendingChan := range b.PendingChannels {
		for _, assetOutput := range pendingChan.LocalOutputs() {
			assetID := assetOutput.Proof.Val.Asset.ID()

			assetIDStr := hex.EncodeToString(assetID[:])
			assetName := assetOutput.Proof.Val.Asset.Tag

			assetBalance, ok := resp.PendingChannels[assetIDStr]
			if !ok {
				assetBalance = &rfqmsg.JsonAssetBalance{
					AssetID: assetIDStr,
					Name:    assetName,
				}
				resp.PendingChannels[assetIDStr] = assetBalance
			}

			assetBalance.LocalBalance += assetOutput.Amount.Val
		}

		for _, assetOutput := range pendingChan.RemoteOutputs() {
			assetID := assetOutput.Proof.Val.Asset.ID()

			assetIDStr := hex.EncodeToString(assetID[:])
			assetName := assetOutput.Proof.Val.Asset.Tag

			assetBalance, ok := resp.PendingChannels[assetIDStr]
			if !ok {
				assetBalance = &rfqmsg.JsonAssetBalance{
					AssetID: assetIDStr,
					Name:    assetName,
				}
				resp.PendingChannels[assetIDStr] = assetBalance
			}

			assetBalance.RemoteBalance += assetOutput.Amount.Val
		}
	}

	return json.Marshal(resp)
}

// ReadBalanceCustomData reads the content of a BalanceCustomData struct from a
// byte slice.
func ReadBalanceCustomData(balanceData []byte) (*BalanceCustomData, error) {
	balanceDataReader := bytes.NewReader(balanceData)

	// The first entry is the number of open channels.
	numOpenChannels, err := wire.ReadVarInt(balanceDataReader, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to read number of open "+
			"channels: %w", err)
	}

	result := &BalanceCustomData{
		OpenChannels: make([]*Commitment, numOpenChannels),
	}
	for i := uint64(0); i < numOpenChannels; i++ {
		result.OpenChannels[i], err = ReadCommitment(
			balanceDataReader, uint32(len(balanceData)),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to read open channel: "+
				"%w", err)
		}
	}

	// The next entry is the number of pending channels.
	numPendingChannels, err := wire.ReadVarInt(balanceDataReader, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to read number of pending "+
			"channels: %w", err)
	}

	result.PendingChannels = make([]*Commitment, numPendingChannels)
	for i := uint64(0); i < numPendingChannels; i++ {
		result.PendingChannels[i], err = ReadCommitment(
			balanceDataReader, uint32(len(balanceData)),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to read pending "+
				"channel: %w", err)
		}
	}

	return result, nil
}

// replaceCloseOutCustomChannelData replaces the custom channel data in the
// given close output with the JSON representation of the custom data.
func replaceCloseOutCustomChannelData(localOut *lnrpc.CloseOutput) error {
	if len(localOut.CustomChannelData) == 0 {
		return nil
	}

	closeData, err := DecodeAuxShutdownMsg(localOut.CustomChannelData)
	if err != nil {
		return fmt.Errorf("error reading custom close data: %w", err)
	}

	jsonCloseData := rfqmsg.JsonCloseOutput{
		BtcInternalKey: hex.EncodeToString(
			closeData.BtcInternalKey.Val.SerializeCompressed(),
		),
		AssetInternalKey: hex.EncodeToString(
			closeData.AssetInternalKey.Val.SerializeCompressed(),
		),
		ScriptKeys: make(
			map[string]string, len(closeData.ScriptKeys.Val),
		),
	}

	for assetID, scriptKey := range closeData.ScriptKeys.Val {
		jsonCloseData.ScriptKeys[assetID.String()] = hex.EncodeToString(
			scriptKey.SerializeCompressed(),
		)
	}

	localOut.CustomChannelData, err = json.Marshal(jsonCloseData)
	if err != nil {
		return fmt.Errorf("error converting custom close data to "+
			"JSON: %w", err)
	}

	return nil
}

// ParseCustomChannelData parses the custom channel data in the given lnd RPC
// message and converts it to JSON, replacing it inline.
func ParseCustomChannelData(msg proto.Message) error {
	switch m := msg.(type) {
	case *lnrpc.ListChannelsResponse:
		for idx := range m.Channels {
			rpcChannel := m.Channels[idx]

			if len(rpcChannel.CustomChannelData) == 0 {
				continue
			}

			channelData, err := ReadChannelCustomData(
				rpcChannel.CustomChannelData,
			)
			if err != nil {
				return fmt.Errorf("error reading custom "+
					"channel data: %w", err)
			}

			rpcChannel.CustomChannelData, err = channelData.AsJson()
			if err != nil {
				return fmt.Errorf("error converting custom "+
					"channel data to JSON: %w", err)
			}
		}

	case *lnrpc.ChannelBalanceResponse:
		if len(m.CustomChannelData) == 0 {
			return nil
		}

		balanceData, err := ReadBalanceCustomData(m.CustomChannelData)
		if err != nil {
			return fmt.Errorf("error reading custom balance "+
				"data: %w", err)
		}

		m.CustomChannelData, err = balanceData.AsJson()
		if err != nil {
			return fmt.Errorf("error converting custom balance "+
				"data to JSON: %w", err)
		}

	case *lnrpc.PendingChannelsResponse:
		for idx := range m.PendingOpenChannels {
			pendingOpen := m.PendingOpenChannels[idx]
			rpcChannel := pendingOpen.Channel

			if rpcChannel == nil {
				continue
			}

			if len(rpcChannel.CustomChannelData) == 0 {
				continue
			}

			channelData, err := ReadChannelCustomData(
				rpcChannel.CustomChannelData,
			)
			if err != nil {
				return fmt.Errorf("error reading custom "+
					"channel data: %w", err)
			}

			rpcChannel.CustomChannelData, err = channelData.AsJson()
			if err != nil {
				return fmt.Errorf("error converting custom "+
					"channel data to JSON: %w", err)
			}
		}

	case *lnrpc.CloseStatusUpdate:
		closeUpd, ok := m.Update.(*lnrpc.CloseStatusUpdate_ChanClose)
		if !ok {
			return nil
		}

		localOut := closeUpd.ChanClose.LocalCloseOutput
		if localOut != nil {
			err := replaceCloseOutCustomChannelData(localOut)
			if err != nil {
				return fmt.Errorf("error replacing local "+
					"custom close data: %w", err)
			}
		}

		remoteOut := closeUpd.ChanClose.RemoteCloseOutput
		if remoteOut != nil {
			err := replaceCloseOutCustomChannelData(remoteOut)
			if err != nil {
				return fmt.Errorf("error replacing remote "+
					"custom close data: %w", err)
			}
		}

	case *lnrpc.Route:
		if len(m.CustomChannelData) == 0 {
			return nil
		}

		parsedHtlc, err := rfqmsg.DecodeHtlc(m.CustomChannelData)
		if err != nil {
			return fmt.Errorf("error parsing custom "+
				"channel data: %w", err)
		}

		m.CustomChannelData, err = parsedHtlc.AsJson()
		if err != nil {
			return fmt.Errorf("error converting custom "+
				"channel data to JSON: %w", err)
		}

	case *lnrpc.Invoice:
		for idx := range m.Htlcs {
			htlc := m.Htlcs[idx]

			if len(htlc.CustomChannelData) == 0 {
				continue
			}

			parsedHtlc, err := rfqmsg.DecodeHtlc(
				htlc.CustomChannelData,
			)
			if err != nil {
				return fmt.Errorf("error parsing custom "+
					"channel data: %w", err)
			}

			htlc.CustomChannelData, err = parsedHtlc.AsJson()
			if err != nil {
				return fmt.Errorf("error converting custom "+
					"channel data to JSON: %w", err)
			}
		}
	}

	return nil
}
