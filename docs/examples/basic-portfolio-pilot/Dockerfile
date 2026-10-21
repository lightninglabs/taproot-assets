FROM golang:1.26.8-alpine3.23@sha256:a8fa79c5bd40d880b52bd3b6d7669ecdcfd00e85facdd427d279efb5ddd79cb1 AS builder

RUN apk add --no-cache alpine-sdk make

COPY . /build/taproot-assets
WORKDIR /build/taproot-assets

RUN go build -o /go/bin/portfolio-pilot \
    ./docs/examples/basic-portfolio-pilot

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/portfolio-pilot /bin/

ENTRYPOINT ["portfolio-pilot"]
