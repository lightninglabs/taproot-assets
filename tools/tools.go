//go:build tools

package tapd

// The other imports represent our build tools. Instead of defining a commit we
// want to use for those golang based tools, we use the go mod versioning system
// to unify the way we manage dependencies. So we define our build tool
// dependencies here and pin the version in go.mod.
import (
	_ "github.com/btcsuite/btcd"
	_ "github.com/dvyukov/go-fuzz/go-fuzz"
	_ "github.com/dvyukov/go-fuzz/go-fuzz-build"
	_ "github.com/dvyukov/go-fuzz/go-fuzz-dep"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/rinchsan/gosimports/cmd/gosimports"
)
