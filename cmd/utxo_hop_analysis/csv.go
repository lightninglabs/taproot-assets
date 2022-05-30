package main

import (
	"encoding/csv"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/jszwec/csvutil"
)

// default file names and paths
const UTXOEntryFile = "utxo_entries.csv"
const TestUTXOEntryFile = "test_utxo_entries.csv"
const CoinbaseHeightCache = "coinbase_heights.csv"
const TestResultsFile = "test_utxo_results.csv"
const EntryFilePrefix = "txid"
const EntryFolder = "entries"
const ResultsFolder = "results"

// A CSV entry from our processed UTXO dump
type UTXOEntry struct {
	Txid        string
	BlockHeight uint32
	Count       uint16
}

func (e *UTXOEntry) copy() UTXOEntry {
	return UTXOEntry{
		Txid:        strings.Clone(e.Txid),
		BlockHeight: e.BlockHeight,
		Count:       e.Count,
	}
}

type HopHeightList []uint32

// Custom helpers to read/write a list of hops
// Needed since CSV has no spec for writing lists
// We use the ':' character to separate values
func (l HopHeightList) MarshalCSV() ([]byte, error) {
	buf := make([]byte, 0, len(l)*9-1)
	buf = strconv.AppendUint(buf, uint64(l[0]), 10)
	// our hop list needs no separators if it only has one element
	if len(l) == 1 {
		return buf, nil
	}
	for _, val := range l[1:] {
		buf = append(buf, []byte(":")...)
		buf = strconv.AppendUint(buf, uint64(val), 10)
	}
	return buf, nil
}

func (l *HopHeightList) UnmarshalCSV(data []byte) error {
	buf := strings.Split(string(data), ":")
	var parsedVal uint64
	var err error
	for _, val := range buf {
		if parsedVal, err = strconv.ParseUint(val, 10, 32); err != nil {
			return err
		}
		*l = append(*l, uint64to32(parsedVal))
	}
	return nil
}

// Struct for reading/writing to a CSV; we drop the CurrentTx field from the HopList struct,
// as it should always be all zeroes for a complete set of hops.
type HopResult struct {
	// HopHeights stores the block height for each ancestor TX of our original UTXO.
	// Height is stored in descending order; one for each parent TX.
	HopHeights HopHeightList

	// Count is the number of UTXOs created by the Tx specified by Txid.
	Count uint16

	// Txid is the Txid of the TX that starts the hop list / original child.
	Txid string

	// StartHeight is the block height of the original child TX.
	// This should match the first entry in HopHeights.
	StartHeight uint32
}

// Convert a HopList to a form suitable for reading/writing
// We drop the CurrentTx field of the HopList
// For any completed HopList, this field should be all 0s
func newHopResult(list HopList) HopResult {
	result := HopResult{
		HopHeights:  make([]uint32, len(list.HopHeights)),
		Count:       list.Count,
		Txid:        list.Txid.String(),
		StartHeight: list.StartHeight,
	}
	copy(result.HopHeights, list.HopHeights)
	return result
}

type coinbaseResult struct {
	Txid   string
	Height uint32
}

// manually defined CSV headers for encoding
// var UTXOEntryHeader = []string{"Txid,BlockHeight,Count"}

// Read UTXOs that need to be traced from a CSV and submit to a channel.
func readUTXOEntries(entryFile *os.File, waiter *sync.WaitGroup, entries []UTXOEntry) {
	defer waiter.Done()

	entryIndex := 0
	entryReader := createCustomDecoder(entryFile, UTXOEntry{})

	for {
		var bufEntry UTXOEntry
		if err := entryReader.Decode(&bufEntry); err == nil {
			entries[entryIndex] = bufEntry.copy()
			entryIndex++
		} else if err == io.EOF {
			break
		} else {
			errorLog(err)
		}
	}
	log.Println("entries loaded")
}

func sendUTXOEntries(entries []UTXOEntry, waiter *sync.WaitGroup, jobs chan<- UTXOEntry) {
	defer waiter.Done()

	for _, entry := range entries {
		jobs <- entry
	}
	log.Println("No more jobs")
	close(jobs)
}

// Accept completed HopLists from a channel and write to a CSV.
func writeCompletedHops(outfile *os.File, waiter *sync.WaitGroup,
	results <-chan HopList) {
	defer waiter.Done()

	fileHandle, hopEncoder := createEncoder(outfile, []string{})

	var entry HopResult
	for result := range results {
		entry = newHopResult(result)
		if err := hopEncoder.Encode(entry); err != nil {
			errorPanic(err)
		}
	}
	fileHandle.Flush()
}

// Write a filled coinbaseCache to a CSV.
func writeCoinbaseCache(outfile *os.File, cache coinbaseCache) {
	fileHandle, cacheEncoder := createEncoder(outfile, []string{})
	var entry coinbaseResult
	for txid, height := range cache {
		entry = coinbaseResult{txid.String(), height}
		if err := cacheEncoder.Encode(entry); err != nil {
			errorPanic(err)
		}
	}
	fileHandle.Flush()
}

// Read a filled coinbaseCache from a CSV.
func readCoinbaseCache(cacheFile *os.File) coinbaseCache {
	coinbaseDecoder := createDecoder(cacheFile)
	cache := make(map[chainhash.Hash]uint32)
	for {
		var coinbaseTX coinbaseResult
		if err := coinbaseDecoder.Decode(&coinbaseTX); err == nil {
			txid, err := chainhash.NewHashFromStr(coinbaseTX.Txid)
			errorLog(err)
			cache[*txid] = coinbaseTX.Height
		} else if err == io.EOF {
			break
		} else {
			errorLog(err)
		}
	}
	return cache
}

// Fail if our file already exists to prevent overwriting
func createCSV(name string) (*os.File, error) {
	filePath := localPath(name)
	if fileNoExist(filePath) {
		return os.Create(filePath)
	} else {
		return nil, nil
	}
}

// Have to expose file handle to allow for proper closing later on
func openCSV(name string) (*os.File, error) {
	filePath := localPath(name)
	return os.Open(filePath)
}

// needed for CSV files without a header
func createCustomDecoder(file *os.File,
	datatype interface{}) *csvutil.Decoder {
	fileReader := csv.NewReader(file)
	header, err := csvutil.Header(datatype, "csv")
	errorPanic(err)
	fileDecoder, err := csvutil.NewDecoder(fileReader, header...)
	errorPanic(err)
	return fileDecoder
}

// Create CSV decoder needed to fill structs from a file.
func createDecoder(file *os.File) *csvutil.Decoder {
	fileReader := csv.NewReader(file)
	fileDecoder, err := csvutil.NewDecoder(fileReader)
	errorPanic(err)
	return fileDecoder
}

// Create CSV encoder needed to wrtie structs to a file.
func createEncoder(file *os.File, header []string) (
	*csv.Writer, *csvutil.Encoder) {
	fileWriter := csv.NewWriter(file)
	fileEncoder := csvutil.NewEncoder(fileWriter)
	if len(header) != 0 {
		fileEncoder.SetHeader(header)
	}
	return fileWriter, fileEncoder
}
