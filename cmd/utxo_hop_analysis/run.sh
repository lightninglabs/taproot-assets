#!/bin/bash

# debug potential race conditions
# go build -race
go build

# clear previous results
rm "$(pwd)"/results/*
rm "$(pwd)"/test_utxo_results.csv

DATE=$(date -u +%d_%m_%y_%H-%M-%S)
TRACE="trace_$DATE.out"
CPUPROF="prof_$DATE.prof"
MEMPROF="memprof_$DATE.mprof"

# profile our build
# TODO: actual flags to select profile mode?
# time ./utxo_hop_analysis -cpuprofile "$CPUPROF" -memprofile "$MEMPROF"
# time ./utxo_hop_analysis -cpuprofile "$CPUPROF"
time ./utxo_hop_analysis -cpuprofile "$CPUPROF" -trace "$TRACE"
# time ./utxo_hop_analysis
