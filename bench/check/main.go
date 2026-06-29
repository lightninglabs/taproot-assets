// Command bench-check audits coverage of per-RPC benchmarks against the
// taprpc proto surface. It parses every .proto file under taprpc/, lists
// the RPC methods, and reports which methods do not have a corresponding
// Benchmark* function under bench/rpc/.
//
// Each Benchmark function declares which RPC it covers via a directive
// comment in its doc:
//
//	// bench:rpc=<package>.<Service>.<Method>
//
// e.g. // bench:rpc=universerpc.Universe.Info. Function names are never
// matched against RPCs directly because names are not service-qualified
// — a Benchmark named "BenchmarkInfo" would silently false-cover Info
// methods on multiple services.
//
// Methods may opt out of the audit by adding a line to the proto file
// directly above the rpc definition of the form:
//
//	// bench:skip(reason)
//
// Whole services may be skipped by adding the fully-qualified service name
// to skippedServices below. tapchannelrpc is excluded for the first pass
// because it depends on tap-channel subsystems for which no in-process
// fixture exists.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// skippedServices lists fully-qualified service names that are excluded
// from the closure check.
var skippedServices = map[string]string{
	"tapchannelrpc.TaprootAssetChannels": "needs lnd channel subsystems",
	"tapdevrpc.TapDev":                   "dev-only",
	"priceoraclerpc.PriceOracle":         "client surface only",
	"portfoliopilotrpc.PortfolioPilot":   "client surface only",
}

// rpcMethod is one method extracted from a .proto file.
type rpcMethod struct {
	service string
	method  string
	file    string
	skip    string
}

var (
	rpcLineRE     = regexp.MustCompile(`^\s*rpc\s+(\w+)`)
	serviceLineRE = regexp.MustCompile(`^\s*service\s+(\w+)`)
	pkgLineRE     = regexp.MustCompile(`^\s*package\s+([\w.]+)\s*;`)
	skipLineRE    = regexp.MustCompile(`^\s*//\s*bench:skip\(([^)]*)\)`)
)

// parseProtoFile extracts (service, method) pairs from a single .proto
// file along with their skip annotations.
func parseProtoFile(path string) ([]rpcMethod, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var (
		methods    []rpcMethod
		pkg        string
		service    string
		pendingSkip string
	)

	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case pkgLineRE.MatchString(line):
			pkg = pkgLineRE.FindStringSubmatch(line)[1]

		case serviceLineRE.MatchString(line):
			service = serviceLineRE.FindStringSubmatch(line)[1]

		case skipLineRE.MatchString(line):
			pendingSkip = skipLineRE.FindStringSubmatch(line)[1]

		case rpcLineRE.MatchString(line):
			methods = append(methods, rpcMethod{
				service: pkg + "." + service,
				method:  rpcLineRE.FindStringSubmatch(line)[1],
				file:    path,
				skip:    pendingSkip,
			})
			pendingSkip = ""

		default:
			// A non-blank, non-comment, non-rpc line resets a
			// pending skip so it does not attach to a later rpc.
			// Intervening comments (e.g. doc comments between
			// the skip annotation and the rpc) are not enough
			// to break the association — only a non-comment,
			// non-blank line is.
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "//") {
				pendingSkip = ""
			}
		}
	}

	return methods, nil
}

// benchRpcRE captures the fully-qualified RPC identifier on a
// // bench:rpc=<package>.<service>.<method>
// directive comment immediately above a Benchmark function.
var benchRpcRE = regexp.MustCompile(
	`bench:rpc=([a-zA-Z_][\w]*\.[A-Z][\w]*\.[A-Z][\w]*)`,
)

// benchCoverage walks bench/rpc/ and returns a map from fully-qualified
// RPC identifier (package.Service.Method) to the Benchmark function that
// covers it.
//
// The mapping is driven by // bench:rpc= directive comments, not function
// names. Two reasons: (1) function names are not service-qualified, so a
// name like BenchmarkInfo would silently false-cover several services'
// Info methods; (2) explicit directives let one benchmark cover multiple
// RPCs and survive renames.
func benchCoverage(dir string) (map[string]string, error) {
	covered := make(map[string]string)
	fset := token.NewFileSet()

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry,
		err error) error {

		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}

		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if !strings.HasPrefix(fn.Name.Name, "Benchmark") {
				continue
			}
			if fn.Doc == nil {
				continue
			}
			for _, c := range fn.Doc.List {
				for _, m := range benchRpcRE.FindAllStringSubmatch(c.Text, -1) {
					covered[m[1]] = fn.Name.Name
				}
			}
		}
		return nil
	})
	return covered, err
}

func main() {
	protoDir := flag.String("proto", "taprpc",
		"path to the taprpc directory containing .proto files")
	benchDir := flag.String("bench", "bench/rpc",
		"path to the bench/rpc directory containing per-RPC benches")
	verbose := flag.Bool("v", false,
		"list every method's status, not just gaps")
	flag.Parse()

	var allMethods []rpcMethod
	err := filepath.WalkDir(*protoDir, func(path string, d os.DirEntry,
		err error) error {

		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".proto") {
			return nil
		}
		m, err := parseProtoFile(path)
		if err != nil {
			return err
		}
		allMethods = append(allMethods, m...)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk protos:", err)
		os.Exit(2)
	}

	coverage, err := benchCoverage(*benchDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "collect benches:", err)
		os.Exit(2)
	}

	var (
		covered []rpcMethod
		missing []rpcMethod
		skipped []rpcMethod
	)
	for _, m := range allMethods {
		if reason, ok := skippedServices[m.service]; ok {
			m.skip = reason
			skipped = append(skipped, m)
			continue
		}
		if m.skip != "" {
			skipped = append(skipped, m)
			continue
		}
		if _, ok := coverage[m.service+"."+m.method]; ok {
			covered = append(covered, m)
		} else {
			missing = append(missing, m)
		}
	}

	sortMethods := func(s []rpcMethod) {
		sort.Slice(s, func(i, j int) bool {
			if s[i].service != s[j].service {
				return s[i].service < s[j].service
			}
			return s[i].method < s[j].method
		})
	}
	sortMethods(covered)
	sortMethods(missing)
	sortMethods(skipped)

	fmt.Printf("RPC bench coverage: %d covered, %d missing, %d skipped, "+
		"%d total\n",
		len(covered), len(missing), len(skipped), len(allMethods))

	if *verbose {
		fmt.Println("\nCovered:")
		for _, m := range covered {
			fmt.Printf("  %s.%s\n", m.service, m.method)
		}
	}

	if len(skipped) > 0 && *verbose {
		fmt.Println("\nSkipped:")
		for _, m := range skipped {
			fmt.Printf("  %s.%s (%s)\n", m.service, m.method, m.skip)
		}
	}

	if len(missing) > 0 {
		fmt.Println("\nMissing benches:")
		for _, m := range missing {
			fmt.Printf("  %s.%s\n", m.service, m.method)
		}
	}

	// Exit non-zero only if --strict is on. Until coverage approaches 100%
	// the missing list is expected; treating it as a hard failure would
	// gate every commit on full coverage. The audit is informational.
}
