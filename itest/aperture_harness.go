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
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// ApertureHarness is an integration testing harness for the aperture service.
type ApertureHarness struct {
	// ListenAddr is the address that the aperture service is listening on.
	ListenAddr string

	// service is the instance of the aperture service that is running.
	Service *aperture.Aperture
}

// NewApertureHarness creates a new instance of the aperture service. It returns
// a harness which includes useful values for testing.
func NewApertureHarness(t *testing.T, port int) *ApertureHarness {
	// Create a temporary directory for the aperture service to use.
	baseDir := filepath.Join(t.TempDir(), "aperture")
	err := os.MkdirAll(baseDir, os.ModePerm)
	require.NoError(t, err)

	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := &aperture.Config{
		Insecure:   false,
		DebugLevel: "debug",
		ListenAddr: listenAddr,
		Authenticator: &aperture.AuthConfig{
			Disable: true,
		},
		DatabaseBackend: "sqlite",
		Sqlite:          aperture.DefaultSqliteConfig(),
		HashMail: &aperture.HashMailConfig{
			Enabled:               true,
			MessageRate:           time.Millisecond,
			MessageBurstAllowance: int(math.MaxInt32),
		},
		Prometheus: &aperture.PrometheusConfig{},
		Tor:        &aperture.TorConfig{},
		BaseDir:    baseDir,
	}
	service := aperture.NewAperture(cfg)

	return &ApertureHarness{
		ListenAddr: listenAddr,
		Service:    service,
	}
}

// Start starts the aperture service.
func (h *ApertureHarness) Start(errChan chan error) error {
	// If not given, construct a channel to signal any errors produced by
	// the aperture service.
	if errChan == nil {
		errChan = make(chan error)
	}

	// Start the aperture service.
	err := h.Service.Start(errChan)
	if err != nil {
		return err
	}

	// Check for error produced while starting.
	select {
	case err := <-errChan:
		return fmt.Errorf("error starting aperture: %w", err)
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
		apertureAddr := fmt.Sprintf("https://%s/dummy", h.ListenAddr)
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
	if err != nil {
		return err
	}

	return nil
}

// Stop stops the aperture service.
func (h *ApertureHarness) Stop() error {
	return h.Service.Stop()
}

// Ensure that ApertureHarness implements the proof.CourierHarness interface.
var _ proof.CourierHarness = (*ApertureHarness)(nil)
