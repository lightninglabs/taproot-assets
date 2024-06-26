#!/bin/bash

set -e

# Get the latest version number from the migration file names.
migrations_path="tapdb/sqlc/migrations"
latest_file_version=$(ls -r $migrations_path | grep .up.sql | head -1 | cut -d_ -f1)

# Force base 10 interpretation, getting rid of the leading zeroes.
latest_file_version=$((10#$latest_file_version))

# Check the value in migrations.go.
file_path="tapdb/migrations.go"
latest_code_version=$(grep -oP 'LatestMigrationVersion\s*=\s*\K\d+' "$file_path")

if [ "$latest_file_version" -ne "$latest_code_version" ]; then
    echo "Latest migration version in file names: $latest_file_version"
    echo "Latest migration version in code: $latest_code_version"
    exit 1
fi

echo "Latest migration version in file names and code match: $latest_file_version"
