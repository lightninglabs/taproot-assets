package tapgarden

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type legacyMintingStore struct {
	MintingStore

	commits int
}

func (l *legacyMintingStore) CommitSignedGenesisTx(_ context.Context,
	_ *MintingBatch, _ *tapsend.FundedPsbt, _ uint32, _, _, _ []byte) error {

	l.commits++
	return nil
}

type signedPsbtStore struct {
	*legacyMintingStore

	stored bool
}

func (s *signedPsbtStore) StoreSignedGenesisPsbt(_ context.Context,
	_ *btcec.PublicKey, _ *tapsend.FundedPsbt) error {

	s.stored = true
	return nil
}

type internalKeyStore struct {
	*legacyMintingStore

	committedKey keychain.KeyDescriptor
}

type customMintingStore struct {
	*internalKeyStore

	stored bool
}

func (s *customMintingStore) StoreSignedGenesisPsbt(_ context.Context,
	_ *btcec.PublicKey, _ *tapsend.FundedPsbt) error {

	s.stored = true
	return nil
}

func (s *internalKeyStore) CommitSignedGenesisTxWithKey(_ context.Context,
	_ *MintingBatch, key keychain.KeyDescriptor, _ *tapsend.FundedPsbt,
	_ uint32, _, _, _ []byte) error {

	s.committedKey = key
	return nil
}

func TestMintingStoreCompatibilityAdapters(t *testing.T) {
	t.Parallel()

	standardPacket := &tapsend.FundedPsbt{Pkt: &psbt.Packet{}}
	customPacket := &tapsend.FundedPsbt{Pkt: &psbt.Packet{
		Unknowns: []*psbt.Unknown{{
			Key:   fn.CopySlice(customAnchorPsbtMarker),
			Value: []byte{1},
		}},
	}}
	key := keychain.KeyDescriptor{KeyLocator: keychain.KeyLocator{
		Family: 91,
		Index:  17,
	}}

	t.Run("legacy standard commit", func(t *testing.T) {
		t.Parallel()

		store := &legacyMintingStore{}
		err := commitSignedGenesisTx(
			t.Context(), store, &MintingBatch{}, key,
			standardPacket, 0, nil, nil, nil,
		)

		require.NoError(t, err)
		require.Equal(t, 1, store.commits)
	})

	t.Run("legacy custom commit fails closed", func(t *testing.T) {
		t.Parallel()

		store := &legacyMintingStore{}
		err := commitSignedGenesisTx(
			t.Context(), store, &MintingBatch{}, key,
			customPacket, 0, nil, nil, nil,
		)

		require.ErrorContains(t, err, "custom anchor internal keys")
		require.Zero(t, store.commits)
	})

	t.Run("optional internal key capability", func(t *testing.T) {
		t.Parallel()

		base := &legacyMintingStore{}
		store := &internalKeyStore{legacyMintingStore: base}
		err := commitSignedGenesisTx(
			t.Context(), store, &MintingBatch{}, key,
			customPacket, 0, nil, nil, nil,
		)

		require.NoError(t, err)
		require.Equal(t, key.KeyLocator, store.committedKey.KeyLocator)
		require.Zero(t, base.commits)
	})

	t.Run("signed PSBT capability", func(t *testing.T) {
		t.Parallel()

		legacy := &legacyMintingStore{}
		err := storeSignedGenesisPsbt(
			t.Context(), legacy, nil, customPacket,
		)
		require.ErrorContains(t, err, "signed custom genesis")

		partial := &signedPsbtStore{legacyMintingStore: legacy}
		err = storeSignedGenesisPsbt(
			t.Context(), partial, nil, customPacket,
		)
		require.ErrorContains(t, err, "custom anchor internal keys")
		require.False(t, partial.stored)

		store := &customMintingStore{internalKeyStore: &internalKeyStore{
			legacyMintingStore: legacy,
		}}
		err = storeSignedGenesisPsbt(
			t.Context(), store, nil, customPacket,
		)
		require.NoError(t, err)
		require.True(t, store.stored)
	})
}
