# Base Alpine Image to keep it lightweight
FROM alpine:latest

# Set working directory
WORKDIR /app

# Copy the pre-installed tapd and tapcli binaries
# Make sure you call `make install` before building the image
COPY ./tapd /bin/tapd
COPY ./tapcli /bin/tapcli

# Expose necessary ports
EXPOSE 10029
EXPOSE 8089

# Set the entrypoint to tapd
ENTRYPOINT ["tapd"]
