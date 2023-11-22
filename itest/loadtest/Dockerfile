FROM golang:1.21.4 as builder

WORKDIR /app

COPY . /app

ENV CGO_ENABLED=0

RUN make build-loadtest

# FINAL IMAGE
FROM alpine as final

COPY --from=builder /app/loadtest /bin/

ENTRYPOINT ["loadtest"]
