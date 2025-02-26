package test

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lightningnetwork/lnd/lntest/port"
	"google.golang.org/grpc"
)

var (
	// ListenAddrTemplate is the template for the address the mock server
	// listens on.
	ListenAddrTemplate = "localhost:%d"

	// StartupWaitTime is the time we wait for the server to start up.
	StartupWaitTime = 50 * time.Millisecond
)

// StartMockGRPCServer starts a mock gRPC server on a free port and returns the
// address it's listening on. The caller should clean up the server by calling
// the cleanup function.
func StartMockGRPCServer(grpcServer *grpc.Server) (string, func(), error) {
	nextPort := port.NextAvailablePort()
	listenAddr := fmt.Sprintf(ListenAddrTemplate, nextPort)

	grpcListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", nil, fmt.Errorf("mock RPC server unable to listen "+
			"on %s", listenAddr)
	}

	var (
		wg             sync.WaitGroup
		started        = make(chan struct{})
		startupErrChan = make(chan error, 1)
	)
	wg.Add(1)
	go func() {
		defer wg.Done()

		// The goroutine has started, signal the main goroutine.
		close(started)

		err := grpcServer.Serve(grpcListener)
		if err != nil {
			startupErrChan <- fmt.Errorf("mock RPC server unable "+
				"to serve on %s: %v", listenAddr, err)
		}

		close(startupErrChan)
	}()

	// We wait until the goroutine has started before returning the
	// listener address.
	<-started

	// If we get an error during startup, we return it immediately. If we
	// don't get an error now, it means the server has started successfully.
	// Any errors during the server's lifetime will be swallowed though.
	startupWait := time.After(StartupWaitTime)
	select {
	case err := <-startupErrChan:
		return "", nil, err
	case <-startupWait:
	}

	cleanup := func() {
		grpcServer.Stop()
		_ = grpcListener.Close()
		wg.Wait()
	}

	return listenAddr, cleanup, nil
}
