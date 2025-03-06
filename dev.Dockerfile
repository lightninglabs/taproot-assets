FROM golang:1.23.6 as builder

WORKDIR /app

COPY . /app

ENV CGO_ENABLED=0

RUN make release-install TAGS=monitoring

# FINAL IMAGE
FROM alpine as final

COPY --from=builder /go/bin/tapd /bin/
COPY --from=builder /go/bin/tapcli /bin/

EXPOSE 10029
EXPOSE 8089

ENTRYPOINT ["tapd"]
