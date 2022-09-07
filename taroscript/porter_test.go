package taroscript

import (
	"testing"

	"github.com/lightninglabs/taro/address"
	"github.com/stretchr/testify/require"
)

func TestRunPorter(t *testing.T) {
	t.Helper()

	state := initSpendScenario(t)

	// TODO(jhb): Should be a util func
	porterPackage := SendPackage{
		ChainParams:  &address.TestNet3Taro,
		InternalKey:  state.spenderPubKey,
		PrivKey:      state.spenderPrivKey,
		ScriptKey:    state.spenderScriptKey,
		PrevID:       state.asset2PrevID,
		PrevAsset:    state.asset2,
		PrevTaroTree: state.asset2TaroTree,
		Address:      state.address1,
	}

	porterComplete := make(chan bool)
	porterErr := make(chan error)

	porterCfg := PorterConfig{
		Package:        porterPackage,
		CompletionChan: porterComplete,
		ErrChan:        porterErr,
	}

	porter := NewPorter(&porterCfg)

	err := porter.Start()
	require.NoError(t, err)

	for {
		select {
		case <-porterComplete:
			return
		default:
		}
	}
}
