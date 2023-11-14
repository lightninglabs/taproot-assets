# `taproot-assets`'s Reproducible Build System

This package contains the build script that the `taproot-assets` project uses in
order to build binaries for each new release. As of `go1.13`, with some new
build flags, binaries are now reproducible, allowing developers to build the
binary on distinct machines, and end up with a byte-for-byte identical binary.
However, this wasn't _fully_ solved in `go1.13`, as the build system still
includes the directory the binary is built into the binary itself. As a result,
our scripts utilize a work around needed until `go1.13.2`.  

## Building a New Release

### MacOS

The first requirement is to have [`docker`](https://www.docker.com/)
installed locally and running. The second requirement is to have `make`
installed. Everything else (including `golang`) is included in the release
helper image.

To build a release, run the following commands:

```shell
$  git clone https://github.com/lightninglabs/taproot-assets.git
$  cd taproot-assets
$  git checkout <TAG> # <TAG> is the name of the next release/tag
$  make docker-release tag=<TAG>
```

Where `<TAG>` is the name of the next release of `taproot-assets`.

### Linux/Windows (WSL)

No prior set up is needed on Linux or macOS is required in order to build the
release binaries. However, on Windows, the only way to build the release
binaries at the moment is by using the Windows Subsystem Linux. One can build
the release binaries following these steps:

```shell
$  git clone https://github.com/lightninglabs/taproot-assets.git
$  cd taproot-assets
$  git checkout <TAG> # <TAG> is the name of the next release/tag
$  make release tag=<TAG>
```

This will then create a directory of the form `taproot-assets-<TAG>` containing
archives of the release binaries for each supported operating system and
architecture, and a manifest file containing the hash of each archive.

## Verifying a Release

With `go1.13`, it's now possible for third parties to verify release binaries.
Before this version of `go`, one had to trust the release manager(s) to build the
proper binary. With this new system, third parties can now _independently_ run
the release process, and verify that all the hashes of the release binaries
match exactly that of the release binaries produced by said third parties.

To verify a release, one must obtain the following tools (many of these come
installed by default in most Unix systems): `gpg`/`gpg2`, `shashum`, and
`tar`/`unzip`.

Once done, verifiers can proceed with the following steps:

1. Acquire the archive containing the release binaries for one's specific
   operating system and architecture, and the manifest file along with its
   signature.
2. Verify the signature of the manifest file with `gpg --verify
   manifest-<TAG>.txt.sig`. This will require obtaining the PGP keys which
   signed the manifest file, which are included in the release notes.
3. Recompute the `SHA256` hash of the archive with `shasum -a 256 <filename>`,
   locate the corresponding one in the manifest file, and ensure they match
   __exactly__.

At this point, verifiers can use the release binaries acquired if they trust
the integrity of the release manager(s). Otherwise, one can proceed with the
guide to verify the release binaries were built properly by obtaining `shasum`
and `go` (matching the same version used in the release):

4. Extract the release binaries contained within the archive, compute their
   hashes as done above, and note them down.
5. Ensure `go` is installed, matching the same version as noted in the release
   notes. 
6. Obtain a copy of `taproot-assets`'s source code with `git clone
   https://github.com/lightninglabs/taproot-assets` and checkout the source code of the
   release with `git checkout <TAG>`.
7. Proceed to verify the tag with `git verify-tag <TAG>` and compile the
   binaries from source for the intended operating system and architecture with
   `make release sys=OS-ARCH tag=<TAG>`.
8. Extract the archive found in the `taproot-assets-<TAG>` directory created by
   the release script and recompute the `SHA256` hash of the release binaries
   (`tapd` and `tapcli`) with `shasum -a 256 <filename>`. These should match
   __exactly__ as the ones noted above.

## Verifying Docker Images

To verify the `tapd` and `tapcli` binaries inside the
[official provided docker images](https://hub.docker.com/r/lightninglabs/taproot-assets)
against the signed, reproducible release binaries, there is a verification
script in the image that can be called (before starting the container for
example):

```shell
$  docker run --rm --entrypoint="" lightninglabs/taproot-assets:v0.3.0 /verify-install.sh v0.3.0
$  OK=$?
$  if [ "$OK" -ne "0" ]; then echo "Verification failed!"; exit 1; done
$  docker run lightninglabs/taproot-assets [command-line options]
```

# Signing an Existing Manifest File

If you're a developer of `taproot-assets` and are interested in attaching your
signature to the final release archive, the manifest MUST be signed in a manner
that allows your signature to be verified by our verify script
`scripts/verify-install.sh`. 

Assuming you've done a local build for _all_ release targets, then you should
have a file called `manifest-TAG.txt` where `TAG` is the actual release tag
description being signed. The release script expects a particular file name for
each included signature, so we'll need to modify the name of our output
signature during signing.

Assuming `USERNAME` is your current nick as a developer, then the following
command will generate a proper signature:
```shell
$  gpg --detach-sig --output manifest-USERNAME-TAG.sig manifest-TAG.txt
```
