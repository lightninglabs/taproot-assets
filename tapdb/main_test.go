package tapdb

import (
	"flag"
	"os"
	"testing"
)

// defaultRapidChecks caps the number of iterations rapid property
// tests run per check. The library default of 100 dominates the
// package's test runtime, in particular under the race detector. An
// explicit -rapid.checks flag overrides the cap.
const defaultRapidChecks = "25"

// TestMain lowers the default rapid property-test iteration count.
func TestMain(m *testing.M) {
	flag.Parse()

	explicit := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == "rapid.checks" {
			explicit = true
		}
	})
	if !explicit {
		err := flag.Set("rapid.checks", defaultRapidChecks)
		if err != nil {
			panic(err)
		}
	}

	os.Exit(m.Run())
}
