# If you change this value, please change it in the following files as well:
# /.github/workflows/main.yaml
# /Dockerfile
# /dev.Dockerfile
# /make/builder.Dockerfile
# /taprpc/Dockerfile
FROM golang:1.21.0-buster

RUN apt-get update && apt-get install -y git
ENV GOCACHE=/tmp/build/.cache
ENV GOMODCACHE=/tmp/build/.modcache

COPY . /tmp/tools

RUN cd /tmp \
  && mkdir -p /tmp/build/.cache \
  && mkdir -p /tmp/build/.modcache \
  && cd /tmp/tools \
  && go install -trimpath github.com/golangci/golangci-lint/cmd/golangci-lint \
  && chmod -R 777 /tmp/build/ \
  && git config --global --add safe.directory /build

WORKDIR /build
