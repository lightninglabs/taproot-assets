package main

import (
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
