FROM golang:1.25.2-alpine as builder

# Force Go to use the cgo based DNS resolver. This is required to ensure DNS
# queries required to connect to linked containers succeed.
ENV GODEBUG netdns=cgo

# Pass a tag, branch or a commit using build-arg.  This allows a docker
# image to be built from a specified Git state.  The default image
# will use the Git tip of master by default.
ARG checkout="main"
ARG git_url="https://github.com/lightninglabs/taproot-assets"

# Install dependencies and build the binaries.
RUN apk add --no-cache --update alpine-sdk \
    git \
    make \
    gcc \
&&  git clone $git_url /go/src/github.com/lightninglabs/taproot-assets \
&&  cd /go/src/github.com/lightninglabs/taproot-assets \
&&  git checkout $checkout \
&&  make release-install

# Start a new, final image.
FROM alpine as final

# Define a root volume for data persistence.
VOLUME /root/.tapd

# Add utilities for quality of life and SSL-related reasons. We also require
# curl and gpg for the signature verification script.
RUN apk --no-cache add \
    bash \
    jq \
    ca-certificates \
    gnupg \
    curl

# Copy the binaries from the builder image.
COPY --from=builder /go/bin/tapcli /bin/
COPY --from=builder /go/bin/tapd /bin/

# Copy the verification script and keys for signature verification.
COPY --from=builder \
  /go/src/github.com/lightninglabs/taproot-assets/scripts/verify-install.sh \
  /verify-install.sh
COPY --from=builder \
  /go/src/github.com/lightninglabs/taproot-assets/scripts/keys \
  /keys

# Store the SHA256 hash of the binaries that were just produced for later
# verification.
RUN sha256sum /bin/tapd /bin/tapcli > /shasums.txt \
  && cat /shasums.txt

# Expose tapd ports (gRPC, REST).
EXPOSE 10029 8089

# Specify the start command and entrypoint as the tapd daemon.
ENTRYPOINT ["tapd"]
