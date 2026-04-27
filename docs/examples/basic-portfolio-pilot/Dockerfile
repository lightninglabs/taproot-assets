FROM golang:1.25.5-alpine AS builder

RUN apk add --no-cache alpine-sdk make

COPY . /build/taproot-assets
WORKDIR /build/taproot-assets

RUN go build -o /go/bin/portfolio-pilot \
    ./docs/examples/basic-portfolio-pilot

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/portfolio-pilot /bin/

ENTRYPOINT ["portfolio-pilot"]
