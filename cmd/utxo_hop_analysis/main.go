package main

import (
	"flag"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"

	"github.com/btcsuite/btcd/rpcclient"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpuprofile to file")
var memprofile = flag.String("memprofile", "", "write memprofile to file")
var tracedata = flag.String("trace", "", "write trace to file")

func main() {
	flag.Parse()
	if *cpuprofile != "" {
		file, err := os.Create(*cpuprofile)
		errorPanic(err)
		defer file.Close()
		if err := pprof.StartCPUProfile(file); err != nil {
			errorPanic(err)
		}
		defer pprof.StopCPUProfile()
	}

	if *tracedata != "" {
		file, err := os.Create(*tracedata)
		errorPanic(err)
		defer file.Close()
		if err := trace.Start(file); err != nil {
			errorPanic(err)
		}
		defer trace.Stop()
	}

	// Connect to local btcd RPC server using websockets. (vestigial)
	connCfg := createRPCConfig()
	var heightCache blockHashCache
	var coinbaseCache coinbaseCache

	// Read-only context object to store caches and the global RPC config
	ctx := newContext(connCfg, heightCache, coinbaseCache)

	client, err := rpcclient.New(connCfg, nil)
	errorLog(err)
	defer client.Shutdown()

	// Rebuild the block height cache each time
	// NOTE: Takes ~4 seconds to run on a Ryzen 7 5800H
	blockCacheState := fillBlockHashCache(&ctx)
	if !blockCacheState {
		panic("Failed to build block height cache")
	}

	// This feels like the wrong pattern
	// for condiitonal assignment to the file handle?
	coinbaseCacheFile, err := createCSV(CoinbaseHeightCache)
	if coinbaseCacheFile == nil {
		log.Println("Have coinbase cache")
		var err error
		coinbaseCacheFile, err = openCSV(CoinbaseHeightCache)
		errorPanic(err)
		ctx.coinbaseCache = readCoinbaseCache(coinbaseCacheFile)
	} else {
		log.Println("Missing coinbase cache")
		errorPanic(err)
		coinbaseCacheState := fillCoinbaseCache(&ctx)
		if !coinbaseCacheState {
			panic("Failed to build coinbase cache")
		}
		writeCoinbaseCache(coinbaseCacheFile, coinbaseCache)
	}
	defer coinbaseCacheFile.Close()

	// Test input and output
	///*
	testUtxoFile, err := openCSV(TestUTXOEntryFile)
	errorPanic(err)
	defer testUtxoFile.Close()

	testResultsFile, err := createCSV(TestResultsFile)
	errorPanic(err)
	defer testResultsFile.Close()

	entryList := loadEntries(testUtxoFile)

	// Process test input
	log.Println("Processing test input")
	var hopSync sync.WaitGroup
	// async pipeline
	entries := make(chan UTXOEntry, 1)
	results := make(chan HopList, 1)

	hopSync.Add(3)
	go writeCompletedHops(testResultsFile, &hopSync, results)
	go findHops(&ctx, &hopSync, entries, results)
	go sendUTXOEntries(entryList, &hopSync, entries)

	hopSync.Wait()
	//*/

	// Main loop; iterate over input files and start hop finding
	// Running one hop finding instance per file, and files are loaded one by one
	/*
		endFile := 3
		startFile := 0
		for file := startFile; file < endFile; file++ {
			log.Println("Processing file", file)

			inputFilename := getTxidFilename(file, false)
			entryFile, err := openCSV(inputFilename)
			errorPanic(err)
			defer entryFile.Close()

			entryList := loadEntries(entryFile)

			// start writers
			hopSync, results, resultFiles := initWriterPool(file, 1)

			for _, file := range resultFiles {
				defer file.Close()
			}

			// async pipeline
			entries := make(chan UTXOEntry, 16)

			// start the pipeline from back to front?

			// increment WaitGroup outside of the goroutines to avoid a race
			// https://github.com/golang/go/issues/23842
			hopSync.Add(2)
			go findHops(&ctx, hopSync, entries, results)
			go sendUTXOEntries(entryList, hopSync, entries)

			hopSync.Wait()
		}
	*/

	if *memprofile != "" {
		file, err := os.Create(*memprofile)
		errorPanic(err)
		defer file.Close()
		runtime.GC()
		if err := pprof.WriteHeapProfile(file); err != nil {
			errorPanic(err)
		}
	}

	// log.Println("result count:", len(completeHops))
	// printHops(completeHops)
}
