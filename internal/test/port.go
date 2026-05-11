package test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	// defaultNodePort is the start of the range for listening ports of
	// harness nodes.
	defaultNodePort = 10000

	// maxNodePort is the highest port we'll try to allocate.
	maxNodePort = 65535

	// uniquePortFile is the name of the file that is used to store the last
	// port that was used by a node.
	uniquePortFile = "rpctest-port"
)

var (
	portFileMutex sync.Mutex
)

// NextAvailablePort returns the first port that is available for listening by
// a new node, using a lock file to make sure concurrent tasks on the same
// system don't re-use the same port.
func NextAvailablePort() int {
	portFileMutex.Lock()
	defer portFileMutex.Unlock()

	lockFile := filepath.Join(os.TempDir(), uniquePortFile+".lock")
	timeout := time.After(30 * time.Second)

	var (
		lockFileHandle *os.File
		err            error
	)
	for {
		lockFileHandle, err = os.OpenFile(
			lockFile, os.O_CREATE|os.O_EXCL, 0600,
		)
		if err == nil {
			break
		}

		select {
		case <-timeout:
			panic("timeout waiting for lock file")

		case <-time.After(10 * time.Millisecond):
		}
	}

	defer func() {
		_ = lockFileHandle.Close()

		err := os.Remove(lockFile)
		if err != nil {
			panic(fmt.Errorf("couldn't remove lock file: %w", err))
		}
	}()

	portFile := filepath.Join(os.TempDir(), uniquePortFile)
	portBytes, err := os.ReadFile(portFile)
	if err != nil {
		if !os.IsNotExist(err) {
			panic(fmt.Errorf("error reading port file: %w", err))
		}

		portBytes = []byte(strconv.Itoa(defaultNodePort))
	}

	lastPort, err := strconv.Atoi(string(portBytes))
	if err != nil {
		panic(fmt.Errorf("error parsing port: %w", err))
	}

	portRange := maxNodePort - defaultNodePort + 1
	for attempt := 1; attempt <= portRange; attempt++ {
		nextPort := nextPortCandidate(lastPort, attempt)
		addr := fmt.Sprintf(ListenAddrTemplate, nextPort)
		l, err := net.Listen("tcp4", addr)
		if err == nil {
			err := l.Close()
			if err == nil {
				err := os.WriteFile(
					portFile,
					[]byte(strconv.Itoa(nextPort)), 0600,
				)
				if err != nil {
					panic(fmt.Errorf("error updating "+
						"port file: %w", err))
				}

				return nextPort
			}
		}
	}

	panic("no ports available for listening")
}

func nextPortCandidate(lastPort, attempt int) int {
	if lastPort < defaultNodePort || lastPort > maxNodePort {
		lastPort = defaultNodePort
	}

	portRange := maxNodePort - defaultNodePort + 1
	offset := lastPort - defaultNodePort + attempt

	return defaultNodePort + offset%portRange
}
