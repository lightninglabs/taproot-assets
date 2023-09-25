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
  sqlc/sqlc:1.21.0 generate

# Until https://github.com/kyleconroy/sqlc/issues/1334 is fixed, we need to
# manually modify some types so LEFT JOIN queries compile properly.
echo "Fixing LEFT JOIN issue..."
sed -i.bak -E 's/GroupKeyFamily([[:space:]])+int32/GroupKeyFamily\1sql.NullInt32/g' tapdb/sqlc/assets.sql.go
sed -i.bak -E 's/GroupKeyIndex([[:space:]])+int32/GroupKeyIndex\1sql.NullInt32/g' tapdb/sqlc/assets.sql.go

echo "Reformatting modified files.."
go fmt tapdb/sqlc/assets.sql.go
