package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
)

type workerContext struct {
	config         *rpcclient.ConnConfig
	blockHashCache blockHashCache
	coinbaseCache  coinbaseCache
}

func newContext(config *rpcclient.ConnConfig, bhCache blockHashCache,
	cbCache coinbaseCache) workerContext {
	return workerContext{
		config,
		bhCache,
		cbCache,
	}
}

func errorLog(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func errorPanic(e error) {
	if e != nil {
		panic(e)
	}
}

// Safe data type conversions
func int64ToUint32(height int64) uint32 {
	maxUint32 := ^uint32(0)
	if height < 0 || height > int64(maxUint32) {
		errorPanic(errors.New("block height out of range"))
	}
	return uint32(height)
}

func uint64to32(val uint64) uint32 {
	maxUint32 := ^uint32(0)
	if val > uint64(maxUint32) {
		errorPanic(errors.New("uint32 overflow"))
	}
	return uint32(val)
}

func emptyHash() *chainhash.Hash {
	emptyTXID, err := chainhash.NewHashFromStr("")
	errorLog(err)
	return emptyTXID
}

// true indicates the file does not exist
func fileNoExist(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

// Return the location of a file in the project directory
func localPath(name string) string {
	basePath, err := os.Getwd()
	errorPanic(err)
	return filepath.Join(basePath, name)
}

// 4934 total files with splits of 10k lines
func getTxidFilename(val int, output bool) string {
	hex := strconv.FormatInt(int64(val), 16)
	// 4 digit hex string
	for len(hex) < 4 {
		hex = strconv.FormatInt(int64(0), 16) + hex
	}
	filename := EntryFilePrefix + hex
	if output {
		filename = filename + ".csv"
		return addDir(filename, ResultsFolder)
	}
	return addDir(filename, EntryFolder)
}

// Create a set of files to write results to
func createTxidShardFiles(index, count int) []*os.File {
	fileHandles := make([]*os.File, count)

	var filename string
	for i := 0; i < count; i++ {
		filename = getTxidShardFilename(index, i, count)
		log.Println("File handle:", filename)
		fileHandle, err := createCSV(filename)
		errorPanic(err)
		fileHandles[i] = fileHandle
	}

	return fileHandles
}

// Construct a filename for an output file with an index as a suffix
func getTxidShardFilename(val, index, radix int) string {
	hexPrefix := intToHex(val, 4)
	hexSuffix := intToHex(index, radix/16)
	filename := EntryFilePrefix + hexPrefix + "_" + hexSuffix + ".csv"
	return addDir(filename, ResultsFolder)
}

// Convert an int to a 0-padded hex string
func intToHex(val, padlen int) string {
	hex := strconv.FormatInt(int64(val), 16)
	// TODO: should be able to compute # of 0s needed directly
	for len(hex) < padlen {
		hex = "0" + hex
	}
	return hex
}

// Prefix a filename with a path to a directory
func addDir(filename string, dirname string) string {
	return filepath.Join(dirname, filename)
}

func createRPCConfig() *rpcclient.ConnConfig {
	// Connect to local btcd RPC server using websockets.
	btcdCert := filepath.Join(btcutil.AppDataDir("btcd", false), "rpc.cert")
	certs, err := os.ReadFile(btcdCert)
	errorLog(err)

	rpc_user := os.Getenv("BTCD_RPC_USER")
	rpc_pass := os.Getenv("BTCD_RPC_PASS")

	connCfg := &rpcclient.ConnConfig{
		Host:         "localhost:8334",
		Endpoint:     "ws",
		User:         rpc_user,
		Pass:         rpc_pass,
		Certificates: certs,
	}

	return connCfg
}
