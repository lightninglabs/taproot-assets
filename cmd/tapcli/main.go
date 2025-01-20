// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 The Lightning Network Developers

package main

import (
	"os"

	"github.com/lightninglabs/taproot-assets/tapcliutil"
)

func main() {
	// Set up the main CLI app.
	app := tapcliutil.NewApp()
	if err := app.Run(os.Args); err != nil {
		tapcliutil.Fatal(err)
	}
}
