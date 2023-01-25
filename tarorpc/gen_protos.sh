#!/bin/bash

set -e

# generate compiles the *.pb.go stubs from the *.proto files.
function generate() {
  echo "Generating root gRPC server protos"

  PROTOS="taro.proto assetwalletrpc/assetwallet.proto"

  # For each of the sub-servers, we then generate their protos, but a restricted
  # set as they don't yet require REST proxies, or swagger docs.
  for file in $PROTOS; do
    DIRECTORY=$(dirname "${file}")
    echo "Generating protos from ${file}, into ${DIRECTORY}"

    # Generate the protos.
    protoc -I/usr/local/include -I. \
      --go_out . --go_opt paths=source_relative \
      --go-grpc_out . --go-grpc_opt paths=source_relative \
      "${file}"

    # Generate the REST reverse proxy.
    annotationsFile=${file//proto/yaml}
    protoc -I/usr/local/include -I. \
      --grpc-gateway_out . \
      --grpc-gateway_opt logtostderr=true \
      --grpc-gateway_opt paths=source_relative \
      --grpc-gateway_opt grpc_api_configuration=${annotationsFile} \
      "${file}"

    # Generate the swagger file which describes the REST API in detail.
    protoc -I/usr/local/include -I. \
      --openapiv2_out . \
      --openapiv2_opt logtostderr=true \
      --openapiv2_opt grpc_api_configuration=${annotationsFile} \
      --openapiv2_opt json_names_for_fields=false \
      "${file}"
  done

  # Generate the JSON/WASM client stubs.
  falafel=$(which falafel)
  pkg="tarorpc"
  opts="package_name=$pkg,js_stubs=1,build_tags=// +build js"
  protoc -I/usr/local/include -I. -I.. \
    --plugin=protoc-gen-custom=$falafel\
    --custom_out=. \
    --custom_opt="$opts" \
    taro.proto

  PACKAGES="assetwalletrpc"
  for package in $PACKAGES; do

    opts="package_name=$package,manual_import=$manual_import,js_stubs=1,build_tags=// +build js"
    pushd $package
    protoc -I/usr/local/include -I. -I.. \
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

# Compile and format the tarorpc package.
pushd tarorpc
format
generate
popd

if [[ "$COMPILE_MOBILE" == "1" ]]; then
  pushd mobile
  ./gen_bindings.sh $FALAFEL_VERSION
  popd
fi
