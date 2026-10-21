# The alpine variant suffices for linting: the repo is pure Go (all
# builds set CGO_ENABLED=0 and no file imports "C"), so the C toolchain
# and extra version control systems shipped by the bookworm variant are
# dead weight. With no C compiler present, Go disables cgo on its own,
# matching the release build configuration.
FROM golang:1.26.8-alpine3.23@sha256:a8fa79c5bd40d880b52bd3b6d7669ecdcfd00e85facdd427d279efb5ddd79cb1

RUN apk add --no-cache git
ENV GOCACHE=/tmp/build/.cache
ENV GOMODCACHE=/tmp/build/.modcache

COPY . /tmp/tools

# The build/module caches are wiped after the install because they are
# shadowed at runtime anyway: the Makefile always mounts volumes (or CI
# bind mounts) over GOCACHE/GOMODCACHE. Keeping them would only bloat
# the image by roughly 800MB.
RUN cd /tmp/tools \
  && go install -trimpath github.com/golangci/golangci-lint/v2/cmd/golangci-lint \
  && go clean -cache -modcache \
  && mkdir -p /tmp/build/.cache /tmp/build/.modcache \
  && chmod -R 777 /tmp/build/ \
  && git config --global --add safe.directory /build

WORKDIR /build
