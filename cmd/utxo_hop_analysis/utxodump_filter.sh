#!/bin/bash

# $1 is file; CSV dump of utxo set with form TXID,HEIGHT

# sort by TXID to allow for uniqueness checking
# Count duplicate entries (TXs with multiple UTXOs)
# Sort TXIDs by UTXO count, and write the UTXO count as the third CSV field
sort "$1" | uniq -c | awk '{ print $2,$3","$1 }' | sort -nr -k 3 -t , | sed 's/ //g' > "$(pwd)"/utxo_unique_txids.csv