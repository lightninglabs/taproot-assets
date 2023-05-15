# IMAGE FOR BUILDING
FROM golang:1.20.4 as builder 

WORKDIR /app

COPY . /app

ENV CGO_ENABLED=0

RUN make install

# FINAL IMAGE
FROM alpine as final

COPY --from=builder /go/bin/tapd /bin/
COPY --from=builder /go/bin/tarocli /bin/

EXPOSE 10029
EXPOSE 8089

ENTRYPOINT ["tapd"]