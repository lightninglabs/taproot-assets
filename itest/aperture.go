package itest

import (
	"crypto/tls"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lightninglabs/aperture"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// ApertureHarness is an integration testing harness for the aperture service.
type ApertureHarness struct {
	// ListenAddr is the address that the aperture service is listening on.
	ListenAddr string

	// TlsCertPath is the path to the TLS certificate that the aperture
	// service is using.
	TlsCertPath string

	// service is the instance of the aperture service that is running.
	Service *aperture.Aperture
}

// setupApertureHarness creates a new instance of the aperture service and
// starts it. It returns a harness which includes useful values for testing.
func setupApertureHarness(t *testing.T) ApertureHarness {
	// Create a temporary directory for the aperture service to use.
	baseDir := filepath.Join(t.TempDir(), "aperture")
	err := os.MkdirAll(baseDir, os.ModePerm)
	require.NoError(t, err)

	listenAddr := fmt.Sprintf("127.0.0.1:%d", nextAvailablePort())

	cfg := &aperture.Config{
		Insecure:   false,
		DebugLevel: "debug",
		ListenAddr: listenAddr,
		Authenticator: &aperture.AuthConfig{
			Disable: true,
		},
		Etcd: &aperture.EtcdConfig{},
		HashMail: &aperture.HashMailConfig{
			Enabled:               true,
			MessageRate:           time.Millisecond,
			MessageBurstAllowance: math.MaxUint32,
		},
		Prometheus: &aperture.PrometheusConfig{},
		Tor:        &aperture.TorConfig{},
		BaseDir:    baseDir,
	}
	service := aperture.NewAperture(cfg)

	// Start aperture service asynchronously.
	t.Logf("Starting aperture service on %s", listenAddr)
	errChan := make(chan error)
	require.NoError(t, service.Start(errChan))

	// Check for error produced while starting.
	select {
	case err := <-errChan:
		t.Fatalf("error starting aperture: %v", err)
	default:
	}

	// Ping service to ensure successful start.
	apertureStartTimeout := 3 * time.Second
	err = wait.NoError(func() error {
		// Create a http client that will not check for a valid
		// certificate.
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		// Check for successful service start by querying the dummy
		// endpoint.
		apertureAddr := fmt.Sprintf("https://%s/dummy", listenAddr)
		resp, err := client.Get(apertureAddr)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("invalid status: %d", resp.StatusCode)
		}

		return nil
	}, apertureStartTimeout)
	require.NoError(t, err)

	return ApertureHarness{
		ListenAddr:  listenAddr,
		TlsCertPath: filepath.Join(baseDir, "tls.cert"),
		Service:     service,
	}
}
