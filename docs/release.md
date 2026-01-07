# `taproot-assets`'s Reproducible Build System

Our release artifacts are designed to be reproducible, meaning, for any
release version:

1) Release binaries produced for any target architecture correspond
   byte-for-byte, independent of what host machine or architecture was
   used to perform the build. For example: if a darwin-arm64 machine and
   a linux-amd64 machine each build release binaries for windows-amd64,
   then those produced binaries will match exactly.

2) These binaries, as well as the source and vendored dependencies
   used to build them, are packaged in archives that can be reproduced
   exactly.

In each case, we confirm an "exact match" by comparing SHA256 digests.

## Building a Release

To build a release, ensure `make` and `git` are installed, and that
[`Docker`](https://www.docker.com/) is installed locally and running.
Then:

```shell
$ git clone https://github.com/lightninglabs/taproot-assets.git
$ cd taproot-assets
$ git checkout "$TAG"
$ make docker-release tag="$TAG"
```

Where `$TAG` is the name of the desired release of `taproot-assets`.

Note that you can also run `make release` to avoid the dependency on
Docker and any base images, but, for verification purposes, you must
ensure to use the same Go toolchain used by the Docker image in order to
produce release binaries consistent with it.

## Verifying a Release

To manually verify a release, ensure that `gpg`/`gpg2`, `shasum`, and
`tar`/`unzip` are installed locally, and then proceed with the following
steps:

1. Download the release manifest (`manifest-$TAG.txt`), as
   well as any desired detached signatures that have been made
   for it (typically named `manifest-$SIGNER-$TAG.sig`). These
   are typically available from the Taproot Assets
   [Releases page][ghrelease] on GitHub, under the 'Assets' header for
   any given release.

   Note that the tag itself can be verified via:

   `git verify-tag "$TAG"`

2. Verify the detached signature of the manifest file with:

   `gpg --verify "manifest-$SIGNER-$TAG.sig" "manifest-$TAG.txt"`

   PGP public keys of Taproot Assets developers can be found in the
   scripts/keys subdirectory of the repository root.

3. Procure the other release artifacts, either by building the release from
   source as [described above](#building-a-release), or by downloading
   the desired archive(s) containing the release binaries from the
   Taproot Assets [Releases page][ghrelease] on GitHub.

4. Recompute the SHA256 hash of each artifact with e.g.  `shasum -a 256
   <filename>`, locate the corresponding digest in the manifest file,
   and ensure they match exactly.

## Verifying Release Binaries in Official Docker Images

To verify the `tapd` and `tapcli` binaries inside the [official provided
Docker images](https://hub.docker.com/r/lightninglabs/taproot-assets)
against the signed, reproducible release binaries, there is a
verification script in the image that can be called (before starting the
container for example):

```shell
$ docker run --rm --entrypoint="" \
    lightninglabs/taproot-assets:"$TAG" /verify-install.sh "$TAG"
$ OK=$?
$ if [ "$OK" -ne "0" ]; then echo "Verification failed!"; exit 1; done
$ docker run lightninglabs/taproot-assets [command-line options]
```

Note that Docker images published for versions v0.7.0 and earlier don't
support this script.

# Attesting a Manifest File

If you're a developer of `taproot-assets` and want to attest a
build manifest, the manifest MUST be signed in a manner that
allows your signature to be verified by our verify script
`scripts/verify-install.sh`.

You will first need to make a pull request adding your signing public
key, named `$SIGNER.asc`, to the scripts/keys subdirectory. Then, build
the release artifacts for *all* targets as described in [Building
a Release](#building-a-release). This will include the checksummed
artifacts manifest, `manifest-$TAG.txt`.

To generate a detached signature for the manifest, perform the following:

```shell
$ gpg --detach-sig --output "manifest-$SIGNER-$TAG.sig" "manifest-$TAG.txt"
```

and then upload it to the 'Assets' of the target release [on
GitHub][ghrelease].

[ghrelease]: https://github.com/lightninglabs/taproot-assets/releases
