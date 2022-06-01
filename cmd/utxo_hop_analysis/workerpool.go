package main

import (
	"os"
	"runtime"
	"sync"

	"github.com/btcsuite/btcd/rpcclient"
)

// Worker that can handle multiple input / job types
func worker[T JobConstraint](jobs <-chan T, results chan<- T, config *rpcclient.ConnConfig) {
	client, err := rpcclient.New(config, nil)
	errorPanic(err)
	defer client.Shutdown()

	for job := range jobs {
		job.execute(client)
		results <- job
	}
}

// Worker pool for writing results to disk across multiple files.
func initWriterPool(index, mult int) (*sync.WaitGroup, chan HopList, []*os.File) {
	workerCount := runtime.NumCPU() * mult
	var writerSync sync.WaitGroup
	results := make(chan HopList, workerCount*4)

	fileHandles := createTxidShardFiles(index, workerCount)

	for i := 0; i < workerCount; i++ {
		// defer fileHandles[i].Close()
		writerSync.Add(1)
		go writeCompletedHops(fileHandles[i], &writerSync, results)

	}

	return &writerSync, results, fileHandles
}

// Load UTXO entries from a file
func loadEntries(entryFile *os.File) []UTXOEntry {
	var entrySync sync.WaitGroup
	entrySync.Add(1)
	// TODO: Need to pass around this line count constant properly
	// NOTE: Slice size must match input file line count
	// Using 10000-line files for mainnet data
	// entryList := make([]UTXOEntry, 10000)
	entryList := make([]UTXOEntry, 3)
	go readUTXOEntries(entryFile, &entrySync, entryList)
	entrySync.Wait()
	return entryList
}

// Worker pool for RPC jobs with adjustable size.
func initWorkerPool[T JobConstraint](mult int, config *rpcclient.ConnConfig) (
	*sync.WaitGroup, chan T, chan T) {
	workerCount := runtime.NumCPU() * mult
	jobs := make(chan T, workerCount)
	results := make(chan T, workerCount)
	var workerSync sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		workerSync.Add(1)
		go func() {
			defer workerSync.Done()
			worker(jobs, results, config)
		}()
	}
	return &workerSync, jobs, results
}
