#!/bin/bash
# This script will check Go-version conformance in relevant docker files. Else, exit with error
# A Makefile linter-target runs this script

# Function to check if a YAML file contains the stipulated Go version after 'GO_VERSION:'
check_go_version() {
    local yamlfile="$1"
    local required_go_version="$2"

    # Use grep to find lines with 'GO_VERSION:'
    local go_lines=$(grep -i 'GO_VERSION:' "$yamlfile" || true)  # Ignore grep exit status

    # Check if any lines specify the Go version
    if [ -n "$go_lines" ]; then
        # Extract the Go version from the file's lines. Example matching strings:
        # GO_VERSION: "1.21.0"
        # GO_VERSION: '1.21.0'
        # GO_VERSION: 1.21.0
        # GO_VERSION:1.21.0
        #   GO_VERSION:1.21.0
        local extracted_go_version=$(echo "$go_lines" | sed -n 's/^[[:space:]]*GO_VERSION:[[:space:]]*\(['\''"]\?\)\?\([0-9]\+\.[0-9]\+\.[0-9]\+\)\(['\''"]\?\)\?/\2/p')

        # Check if the extracted Go version matches the required version
        if [ "$extracted_go_version" != "$required_go_version" ]; then
            echo "Error: $yamlfile specifies Go version '$extracted_go_version', but not version '$required_go_version'."
            exit 1
        else
            echo "$yamlfile specifies Go version $required_go_version."
        fi
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

# Run check_go_version on YAML files present in non pruned directory
find . \
    -path ./vendor -prune -o \
    -type f \
    \( -name "*.yaml" -o -name "*.yml" \) \
    -exec bash -c 'check_go_version $1 '"$target_go_version" bash {} \;

echo "All YAML files pass the Go version check for Go version $target_go_version."
