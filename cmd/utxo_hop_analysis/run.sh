#!/bin/bash

# debug potential race conditions
# go build -race
go build

# clear previous results
rm "$(pwd)"/results/*
rm "$(pwd)"/test_utxo_results.csv

# profile our build
# time ./utxo_hop_analysis -cpuprofile prof.prof -memprofile mprof.mprof
time ./utxo_hop_analysis
