# If you change this value, please change it in the following files as well:
# /.github/workflows/main.yaml
# /Dockerfile
# /make/builder.Dockerfile
# /taprpc/Dockerfile
# /tools/Dockerfile
FROM golang:1.21.0 as builder 

WORKDIR /app

COPY . /app

ENV CGO_ENABLED=0

RUN make install

# FINAL IMAGE
FROM alpine as final

COPY --from=builder /go/bin/tapd /bin/
COPY --from=builder /go/bin/tapcli /bin/

EXPOSE 10029
EXPOSE 8089

ENTRYPOINT ["tapd"]
