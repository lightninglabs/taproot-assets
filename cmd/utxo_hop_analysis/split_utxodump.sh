#!/bin/bash

# maximum 2^4 files, 10000 lines each, with prefix txid
split -a 4 -x -l 10000 utxo_unique_txids_oldest.csv txid
