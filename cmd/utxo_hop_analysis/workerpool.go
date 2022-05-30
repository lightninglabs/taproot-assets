package main

import (
	"os"
	"runtime"
	"sync"

	"github.com/btcsuite/btcd/rpcclient"
)

// Worker that can handle multiple input / job types
func worker[T JobType](jobs <-chan T, results chan<- T, config *rpcclient.ConnConfig) {
	client, err := rpcclient.New(config, nil)
	errorPanic(err)
	defer client.Shutdown()

	for job := range jobs {
		job.execute(client)
		results <- job
	}
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
func initWorkerPool[T JobType](mult int, config *rpcclient.ConnConfig) (
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
