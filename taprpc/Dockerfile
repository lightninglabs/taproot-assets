# Builder stage: compile the protoc plugins and fetch the lnd module.
# Only the resulting binaries and the extracted lnd module are carried
# over into the final image, so the Go toolchain and its caches are
# discarded entirely.
FROM golang:1.26.3-bookworm@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b AS builder

# We don't want any default values for these variables to make sure they're
# explicitly provided by parsing the go.mod file. Otherwise we might forget to
# update them here if we bump the versions.
ARG PROTOBUF_VERSION
ARG GRPC_GATEWAY_VERSION
ARG LND_VERSION

ENV PROTOC_GEN_GO_GRPC_VERSION="v1.1.0"
ENV FALAFEL_VERSION="v0.9.2"
ENV GOMODCACHE=/tmp/build/.modcache

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOBUF_VERSION} \
  && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION} \
  && go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@${GRPC_GATEWAY_VERSION} \
  && go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@${GRPC_GATEWAY_VERSION} \
  && go install github.com/lightninglabs/falafel@${FALAFEL_VERSION} \
  && go install golang.org/x/tools/cmd/goimports@v0.1.7 \
  && go mod download github.com/lightningnetwork/lnd@${LND_VERSION}

# Final stage: gen_protos.sh only needs protoc, clang-format, the plugin
# binaries and the extracted lnd module (for proto includes) at runtime,
# so a slim base without the Go toolchain suffices.
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

RUN apt-get update && apt-get install -y \
  protobuf-compiler='3.21.12*' \
  clang-format='1:14.0*' \
  && rm -rf /var/lib/apt/lists/*

ARG LND_VERSION

ENV FALAFEL_VERSION="v0.9.2"
ENV LND_VERSION=${LND_VERSION}
ENV PATH="/go/bin:${PATH}"

COPY --from=builder /go/bin /go/bin
COPY --from=builder \
  /tmp/build/.modcache/github.com/lightningnetwork/lnd@${LND_VERSION} \
  /tmp/build/.modcache/github.com/lightningnetwork/lnd@${LND_VERSION}

WORKDIR /build

CMD ["/bin/bash", "/build/taprpc/gen_protos.sh"]
