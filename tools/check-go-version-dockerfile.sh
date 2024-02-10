#!/bin/bash
# This script will check Go-version conformance in relevant docker files. Else, exit with error
# A Makefile linter-target runs this script

# Function to check if a Dockerfile contains only the stipulated Go version
check_go_version() {
    local dockerfile="$1"
    local required_go_version="$2"

    # Use grep to find lines with 'FROM golang:'
    local go_lines=$(grep -i '^FROM golang:' "$dockerfile")

    # Check if all lines have the required Go version
    if echo "$go_lines" | grep -q -v "$required_go_version"; then
        echo "Error: $dockerfile does not use Go version $required_go_version exclusively."
        exit 1
    else
        echo "$dockerfile is using Go version $required_go_version."
    fi
}

# Export function to be accessible by subshells e.g. `find -exec`
export -f check_go_version

# Check if the target Go version argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_go_version>"
    exit 1
fi

target_go_version="$1"

# Run check_go_version on Dockerfiles files present in non pruned directory
find . \
    -path ./vendor -prune -o \
    -type f \
    \( -name "*.Dockerfile" -o -name "Dockerfile" \) \
    -exec bash -c 'check_go_version $1 '"$target_go_version" bash {} \;

echo "All Dockerfiles pass the Go version check for Go version $target_go_version."
