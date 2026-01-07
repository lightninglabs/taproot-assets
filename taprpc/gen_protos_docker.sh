#!/bin/bash

set -e

# Directory of the script file, independent of where it's called from.
DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

# Source Docker/Podman detection helper.
source "$DIR/../scripts/docker_helpers.sh"

PROTOBUF_VERSION=$(go list -f '{{.Version}}' -m google.golang.org/protobuf)
GRPC_GATEWAY_VERSION=$(go list -f '{{.Version}}' -m github.com/grpc-ecosystem/grpc-gateway/v2)
LND_VERSION=$(go list -f '{{.Version}}' -m github.com/lightningnetwork/lnd)

echo "Building protobuf compiler docker image..."
"$DOCKER" build -t taproot-assets-protobuf-builder \
  --build-arg PROTOBUF_VERSION="$PROTOBUF_VERSION" \
  --build-arg GRPC_GATEWAY_VERSION="$GRPC_GATEWAY_VERSION" \
  --build-arg LND_VERSION="$LND_VERSION" \
  .

echo "Compiling and formatting *.proto files..."
"$DOCKER" run \
  --rm \
  "${user_args[@]}" \
  -e UID=$UID \
  -e COMPILE_MOBILE \
  -e SUBSERVER_PREFIX \
  -v "$DIR/../:/build" \
  taproot-assets-protobuf-builder
