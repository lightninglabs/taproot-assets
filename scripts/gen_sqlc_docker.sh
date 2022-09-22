#!/bin/bash

set -e

# Directory of the script file, independent of where it's called from.
DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"
# Use the user's cache directories
GOCACHE=`go env GOCACHE`
GOMODCACHE=`go env GOMODCACHE`

echo "Generating sql models and queries in go..."

docker run \
  --rm \
  --user "$UID:$(id -g)" \
  -e UID=$UID \
  -v "$DIR/../:/build" \
  -w /build \
  kjconroy/sqlc:1.15.0 generate

# Until https://github.com/kyleconroy/sqlc/issues/1334 is fixed, we need to
# manually modify some types so LEFT JOIN queries compile properly.
echo "Fixing LEFT JOIN issue..."
sed -i.bak -E 's/FamKeyFamily([[:space:]])+int32/FamKeyFamily\1sql.NullInt32/g' tarodb/sqlite/assets.sql.go
sed -i.bak -E 's/FamKeyIndex([[:space:]])+int32/FamKeyIndex\1sql.NullInt32/g' tarodb/sqlite/assets.sql.go

echo "Reformatting modified files.."
go fmt tarodb/sqlite/assets.sql.go
