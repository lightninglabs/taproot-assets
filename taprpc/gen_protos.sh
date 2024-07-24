#!/bin/bash

set -e

# generate compiles the *.pb.go stubs from the *.proto files.
function generate() {
  echo "Generating root gRPC server protos"

  PROTOS="taprootassets.proto assetwalletrpc/assetwallet.proto
mintrpc/mint.proto rfqrpc/rfq.proto priceoraclerpc/price_oracle.proto
universerpc/universe.proto tapdevrpc/tapdev.proto
tapchannelrpc/tapchannel.proto"

  # For each of the sub-servers, we then generate their protos, but a restricted
  # set as they don't yet require REST proxies, or swagger docs.
  for file in $PROTOS; do
    DIRECTORY=$(dirname "${file}")
    echo "Generating protos from ${file}, into ${DIRECTORY}"

    # Generate the protos.
    protoc -I/usr/local/include -I. \
      -I/tmp/build/.modcache/github.com/lightningnetwork/lnd@${LND_VERSION}/lnrpc \
      --go_out . --go_opt paths=source_relative \
      --go-grpc_out . --go-grpc_opt paths=source_relative \
      "${file}"

    # Generate the REST reverse proxy.
    annotationsFile=${file//proto/yaml}
    protoc -I/usr/local/include -I. \
      -I/tmp/build/.modcache/github.com/lightningnetwork/lnd@${LND_VERSION}/lnrpc \
      --grpc-gateway_out . \
      --grpc-gateway_opt logtostderr=true \
      --grpc-gateway_opt paths=source_relative \
      --grpc-gateway_opt grpc_api_configuration=${annotationsFile} \
      "${file}"

    # Generate the swagger file which describes the REST API in detail.
    protoc -I/usr/local/include -I. \
      -I/tmp/build/.modcache/github.com/lightningnetwork/lnd@${LND_VERSION}/lnrpc \
      --openapiv2_out . \
      --openapiv2_opt logtostderr=true \
      --openapiv2_opt grpc_api_configuration=${annotationsFile} \
      --openapiv2_opt json_names_for_fields=false \
      "${file}"
  done

  # Generate the JSON/WASM client stubs.
  falafel=$(which falafel)
  pkg="taprpc"
  opts="package_name=$pkg,js_stubs=1"
  protoc -I/usr/local/include -I. -I.. \
    -I/tmp/build/.modcache/github.com/lightningnetwork/lnd@${LND_VERSION}/lnrpc \
    --plugin=protoc-gen-custom=$falafel\
    --custom_out=. \
    --custom_opt="$opts" \
    taprootassets.proto

  PACKAGES="assetwalletrpc universerpc mintrpc rfqrpc priceoraclerpc
  tapchannelrpc"
  for package in $PACKAGES; do

    opts="package_name=$package,manual_import=$manual_import,js_stubs=1"
    pushd $package
    protoc -I/usr/local/include -I. -I.. \
      -I/tmp/build/.modcache/github.com/lightningnetwork/lnd@${LND_VERSION}/lnrpc \
      --plugin=protoc-gen-custom=$falafel\
      --custom_out=. \
      --custom_opt="$opts" \
      "$(find . -name '*.proto')"
    popd
  done
}

# format formats the *.proto files with the clang-format utility.
function format() {
  find . -name "*.proto" -print0 | xargs -0 clang-format --style=file -i
}

# Compile and format the taprpc package.
pushd taprpc
format
generate
popd

if [[ "$COMPILE_MOBILE" == "1" ]]; then
  pushd mobile
  ./gen_bindings.sh $FALAFEL_VERSION
  popd
fi
