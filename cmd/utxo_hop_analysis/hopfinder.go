package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/chrispappas/golang-generics-set/set"
)

// HopList tracks the ancestors of a set of UTXOs.
type HopList struct {
	// HopHeights stores the block height for each ancestor TX of our original UTXO.
	// Height is stored in descending order; one for each parent TX.
	HopHeights []uint32

	// CurrentTx is the TXID the oldest known parent TX.
	// The block height of current_tx should match the last value in hop_heights.
	CurrentTx chainhash.Hash

	// Count is the number of UTXOs created by the Tx specified by Txid.
	Count uint16

	// Txid is the Txid of the TX that starts the hop list / original child.
	Txid chainhash.Hash

	// StartHeight is the block height of the original child TX.
	// This should match the first entry in HopHeights.
	StartHeight uint32
}

type HopJob struct {
}

func (h *HopQueue) printHops() {
	for _, hop := range h.queue {
		fmt.Print(hop.HopHeights, " ")
	}
	fmt.Println("")
}

func printHops(h []HopList) {
	for _, hop := range h {
		fmt.Println(hop.HopHeights, len(hop.HopHeights))
	}
	fmt.Println("")
}

// Given a UTXO, initialize a HopList object
func NewHopList(entry UTXOEntry) HopList {
	txid, err := chainhash.NewHashFromStr(entry.Txid)
	errorLog(err)
	txidCopy, err := chainhash.NewHash(txid[:])
	errorLog(err)
	newList := HopList{
		HopHeights:  make([]uint32, 0, 1),
		CurrentTx:   *txid,
		Count:       entry.Count,
		Txid:        *txidCopy,
		StartHeight: entry.BlockHeight,
	}
	return newList
}

// Create a HopList from a given UTXO
// Used to ingest UTXOs and add them to our work queue
func initialHopList(entry UTXOEntry, ctx *workerContext,
	client *rpcclient.Client) []HopList {
	initialHop := NewHopList(entry)
	return initialHop.GetParents(ctx, client)
}

// Add a new hop to a hop list.
func (h *HopList) ExtendHopList(newHop uint32,
	txid *chainhash.Hash) HopList {
	newList := *h
	newList.HopHeights = append(newList.HopHeights, newHop)
	txidCopy, err := chainhash.NewHash(txid[:])
	errorLog(err)
	newList.CurrentTx = *txidCopy
	return newList
}

// Fetch the height and inputs of a transaction.
func GetTxInfo(ctx *workerContext, client *rpcclient.Client,
	txid *chainhash.Hash) (
	uint32, []btcjson.Vin) {
	if coinbaseHeight, ok := ctx.coinbaseCache[*txid]; ok {
		// log.Println("Coinbase cache hit!")
		return coinbaseHeight, []btcjson.Vin{}
	}
	// Use verbose mode to get the TX height
	// TODO: parsing JSON is largest bottleneck atm
	// TODO: Replace verbose RPC call with getRawTransaction?
	// Can get TXID with TxHash, and then use TXID->height cache
	// Would return input array of []*Txin
	verboseTX, err := client.GetRawTransactionVerbose(txid)
	errorLog(err)
	parentHeight := ctx.blockHashCache[verboseTX.BlockHash]
	return parentHeight, verboseTX.Vin
}

// Given an input TXID, look up its height
// Record all the TXIDs for each parent
func GetParentTXIDs(ctx *workerContext, client *rpcclient.Client,
	txid *chainhash.Hash) (uint32, []*chainhash.Hash) {
	// RPC call
	parentTxHeight, TxInputs := GetTxInfo(ctx, client, txid)

	// Short circuit for coinbase TXs
	if len(TxInputs) == 0 {
		// fmt.Printf("txid: %v height: %d \n", txid, parentTxHeight)
		return parentTxHeight, []*chainhash.Hash{emptyHash()}
	}

	// deduplicate TXIDs of parents; only record unique parent TXs
	// TODO: Unneeded allocation?
	// Use []byte instead of string? Should work
	// Also, input array could be []*TxIn
	// Can get TXID with TxIn.PreviousOutpoint.Hash
	// Move this set into the context?
	parentTXIDSet := make(set.Set[string])
	for _, input := range TxInputs {
		parentTXIDSet.Add(input.Txid)
	}
	parentTXIDs := make([]*chainhash.Hash, parentTXIDSet.Len())
	txidIndex := 0
	parentTXIDSet.ForEach(
		func(input string) {
			parentTXID, err := chainhash.NewHashFromStr(input)
			errorLog(err)
			parentTXIDs[txidIndex] = parentTXID
			txidIndex++
		},
	)
	return parentTxHeight, parentTXIDs
}

// Given a HopList, build the hops for each parent TX
func (hop *HopList) GetParents(ctx *workerContext,
	client *rpcclient.Client) []HopList {
	// RPC call
	txHeight, txInputs := GetParentTXIDs(ctx, client, &hop.CurrentTx)
	entryList := make([]HopList, len(txInputs))
	for index, input := range txInputs {
		newHop := hop.ExtendHopList(txHeight, input)
		// log.Printf("next: %v height: %d hops: %d",
		// 	input, txHeight, len(newHop.HopHeights))
		entryList[index] = newHop
	}
	return entryList
}

func findHops(ctx *workerContext, waiter *sync.WaitGroup,
	jobs <-chan UTXOEntry, results chan<- HopList) {
	defer waiter.Done()

	client, err := rpcclient.New(ctx.config, nil)
	errorLog(err)
	defer client.Shutdown()

	var workingHops HopQueue
	var bufferEntry UTXOEntry

	coinbaseHash := emptyHash()
	blankEntry := UTXOEntry{}

	// populate our work queue, and read the next job
	firstEntry := <-jobs
	workingHops.append(initialHopList(firstEntry, ctx, client))
	bufferEntry = <-jobs

	for !workingHops.empty() {
		currentHop := workingHops.pop()
		if currentHop.CurrentTx.IsEqual(coinbaseHash) {
			results <- currentHop
			// finished a job, reset our job buffer
			// add a new job if available
			// otherwise our queue stays empty and we exit
			if workingHops.empty() && bufferEntry != blankEntry {
				// RPC call
				workingHops.append(initialHopList(
					bufferEntry, ctx, client))
				bufferEntry = UTXOEntry{}
				bufferEntry = <-jobs
			}
		} else {
			// RPC call
			workingHops.append(currentHop.GetParents(ctx, client))
		}
	}
	log.Println("No more results")
	close(results)
}

/*
// TODO: Add fan-out and fan-in
func initHopPool(ctx *workerContext, mult int) (
	*sync.WaitGroup, chan UTXOEntry, chan HopList) {
	workerCount := runtime.NumCPU() * mult
	jobs := make(chan UTXOEntry, workerCount*2)
	results := make(chan HopList, workerCount*2)
	var workerSync sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		workerSync.Add(1)
		go func() {
			defer workerSync.Done()
			HopWorker(ctx, &workerSync, jobs, results)
		}()
	}
	return &workerSync, jobs, results
}

func findHops(ctx *workerContext, file int) {
	var pubSubSync sync.WaitGroup

	inputFilename := getTxidInputFilename(file)
	outputFilename := getTxidOutputFilename(file)

	entryFile, err := openCSV(localPath(inputFilename))
	errorPanic(err)
	defer entryFile.Close()

	resultsFile, err := createCSV(localPath(outputFilename))
	errorPanic(err)
	defer resultsFile.Close()

	// TODO: Add fan-out and fan-in
	workerSync, jobs, results := initHopPool(ctx, 2)

	go writeCompletedHops(resultsFile, &pubSubSync, results)
	go readUTXOEntries(entryFile, &pubSubSync, jobs)

	workerSync.Wait()
}
*/

// TODO: Implement a worker pool to accept multiple files
// and create a worker per file
