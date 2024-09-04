## Description

This directory (`itest/loadtest`) includes all files and data related to running
the loadtesting suite for taproot assets daemon. These tests use the existing
itest framework to run against real external running daemons.

The configuration file needs to be named `loadtest.conf` and must be placed on
the working directory in order for the loadtest executable to detect it. A
sample configuration can be found in `loadtest-sample.conf` which includes all
the fields that are required for the tests to run successfully. This includes
connection credentials for the tapd & lnd nodes, as well as a bitcoind backend.

For further tracking and metrics, a prometheus gateway is configured and used by
the loadtests in order to submit any desired data in-flight.

## Building

To create the loadtest executable run `make build-loadtest`. This will
create a `loadtest` binary in your working directory which you can run, given
that you have a correct `loadtest.conf` in the same directory.

The executable will consult the appropriate fields of `loadtest.conf` and it's
going to run the defined test case with the respective config.

Example: To run a mint loadtest which mints batches of `450` assets we will
define `test-case="mint"` and `mint-test-batch-size=450` in our `loadtest.conf`.

## Using dev-resources docker setup

You can use any kind of external running daemon, as long as it's reachable. The
easiest way to spin up some nodes from scratch for the purpose of the loadtests
is to run the `dev-resources/docker-regtest` setup and use `alice`, 
`alice-tapd`, `bob`, `bob-tapd` and the single `bitcoind` instance.