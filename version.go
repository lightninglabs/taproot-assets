// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Heavily inspired by https://github.com/btcsuite/btcd/blob/master/version.go
// Copyright (C) 2015-2022 The Lightning Network Developers

package taprootassets

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"strings"
)

var (
	// Commit stores the current commit of this build, which includes the
	// most recent tag, the number of commits since that tag (if non-zero),
	// the commit hash, and a dirty marker. This should be set using the
	// -ldflags during compilation.
	Commit string

	// CommitHash stores the current commit hash of this build.
	CommitHash string

	// RawTags contains the raw set of build tags, separated by commas.
	RawTags string

	// GoVersion stores the go version that the executable was compiled
	// with.
	GoVersion string
)

// semanticAlphabet is the set of characters that are permitted for use in an
// AppPreRelease.
const semanticAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-."

// These constants define the application version and follow the semantic
// versioning 2.0.0 spec (http://semver.org/).
const (
	// AppMajor defines the major version of this binary.
	AppMajor uint = 0

	// AppMinor defines the minor version of this binary.
	AppMinor uint = 3

	// AppPatch defines the application patch for this binary.
	AppPatch uint = 2

	// AppPreRelease MUST only contain characters from semanticAlphabet
	// per the semantic versioning spec.
	AppPreRelease = "alpha"
)

func init() {
	// Assert that AppPreRelease is valid according to the semantic
	// versioning guidelines for pre-release version and build metadata
	// strings. In particular it MUST only contain characters in
	// semanticAlphabet.
	for _, r := range AppPreRelease {
		if !strings.ContainsRune(semanticAlphabet, r) {
			panic(fmt.Errorf("rune: %v is not in the semantic "+
				"alphabet", r))
		}
	}

	// Get build information from the runtime.
	if info, ok := debug.ReadBuildInfo(); ok {
		GoVersion = info.GoVersion
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				CommitHash = setting.Value

			case "-tags":
				RawTags = setting.Value
			}
		}
	}
}

// Version returns the application version as a properly formed string per the
// semantic versioning 2.0.0 spec (http://semver.org/).
func Version() string {
	return fmt.Sprintf("%s commit=%s", semanticVersion(), Commit)
}

// normalizeVerString returns the passed string stripped of all characters
// which are not valid according to the given alphabet.
func normalizeVerString(str, alphabet string) string {
	var result bytes.Buffer
	for _, r := range str {
		if strings.ContainsRune(alphabet, r) {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// semanticVersion returns the SemVer part of the version.
func semanticVersion() string {
	// Start with the major, minor, and patch versions.
	version := fmt.Sprintf("%d.%d.%d", AppMajor, AppMinor, AppPatch)

	// Append pre-release version if there is one. The hyphen called for
	// by the semantic versioning spec is automatically appended and should
	// not be contained in the pre-release string. The pre-release version
	// is not appended if it contains invalid characters.
	preRelease := normalizeVerString(AppPreRelease, semanticAlphabet)
	if preRelease != "" {
		version = fmt.Sprintf("%s-%s", version, preRelease)
	}

	return version
}
