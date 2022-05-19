# UTXO Hop Analysis

## Goal

Generate data on avg. # of hops from a UTXO back to its ancestor coinbase UTXOs, and the time between each spend going from a coinbase UTXO to current UTXOs.

## Pseudocode

```rust
// Used to track the ancestors of a UTXO.
// Stores a list of block heights, one for each parent TX.
// Also stores a TXID that represents the oldest known parent TX.
// The block height of current_tx should match the last value in hop_heights.
// hop_heights should be sorted in descending order.
struct hop_entry = {
  hop_heights: list<block_height>,
  current_tx: txid
}

// multiple options for implementing this
func is_coinbase(hop_entry) -> bool {}

// RPC call to indexed full node for parent TX lookup
// We only need TX height and the TXIDs for the parents of each input
func fetch_parent_txids(txid) -> (height, list<txids>) {
  raw_tx = getrawtransaction(txid)
  return (raw_tx.height(), raw_tx.inputs().txids())
}

func fetch_parents(child_hop) -> list<hop_entry> {
  current_hop_list = child_hop.hop_heights.clone()
  entry_list = list<hop_entry>
  (tx_height, tx_inputs) = fetch_parent_txids(child_hop.current_tx)
  for parent in tx_inputs {
    new_hop = {
      current_hop_list.clone().append(tx_height),
      parent
    }
    entry_list.append(new_hop)
  }
  return entry_list
}

func main() {
for each UTXO {
  hop_list = list<hop_entry>
  working_list = list<hop_entry>
  // initialize hop list
  initial_hop = { [], UTXO.txid() }
  working_list.append(fetch_parents(initial_hop))
  while working_list.len() != 0 {
    current_hop = working_list.pop_from_front()
    // found a complete hop entry, it ends at a coinbase output
    if is_coinbase(current_hop) {
      hop_list.append(current_hop)
    // incomplete hop entry, continue and append results to working list
    } else {
      new_hops = fetch_parents(current_hop)
      working_list.append(new_hops)
    }
  }
}
// hop_list should contain a list of paths from coinbase outputs to UTXOs
}
```

## Project layout

### Logic

cache - logic for building the blockheight and coinbase TX caches
csv - helpers for reading/writing CSV files
hopfinder - logic for finding the ancestors of UTXOs
main - imports needed files and runs the hop finder
queue - simple queue built on slices to add pop() and multi-element append()
util - misc. helpers
utxo_test - test harness for the hop finder
workerpool - helpers for parallelizing filling of our caches

### Data

coinbase_heights - Cache of coinbase TXIDs -> block heights
test_utxo_entries = Three test UTXOs, described further in utxo_test
test_utxo_results (generated after running) - expected results for hop finding run on test_utxo_entries
entries/ and results/ (not checked in) - Folders for input / output files for mainnet data
