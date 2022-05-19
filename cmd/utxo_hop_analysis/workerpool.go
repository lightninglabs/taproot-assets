package main

import (
	"runtime"
	"sync"

	"github.com/btcsuite/btcd/rpcclient"
)

// Worker that can handle multiple input / job types
func worker(jobs <-chan any, results chan<- any, config *rpcclient.ConnConfig) {
	client, err := rpcclient.New(config, nil)
	errorPanic(err)
	defer client.Shutdown()

	for anyJob := range jobs {
		// job function is decided by job type
		switch job := anyJob.(type) {
		case blockHashJob:
			results <- getBlockHash(client, &job)
		case coinbaseJob:
			results <- getCoinbase(client, &job)
		default:
			panic("invalid type for worker")
		}
	}
}

// Worker pool for RPC jobs with adjustable size.
func initWorkerPool(mult int, config *rpcclient.ConnConfig) (
	*sync.WaitGroup, chan any, chan any) {
	workerCount := runtime.NumCPU() * mult
	jobs := make(chan any, workerCount)
	results := make(chan any, workerCount)
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
