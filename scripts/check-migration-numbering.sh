#!/bin/bash

# The directory containing migration files.
migrations_path="tapdb/sqlc/migrations"

# Check if the directory exists
if [ ! -d "$migrations_path" ]; then
  echo "Directory $migrations_path does not exist."
  exit 1
fi

# is_sql_migration checks if a .up.sql file contains executable SQL
# statements and not just comments/whitespace/semicolons. The logic mirrors the
# Go helper the `migrate` package dependency uses in the `migrate.go` file.
is_sql_migration() {
  local file="$1"
  local cleaned

  cleaned=$(
    perl -0777 -pe '
      s/^\x{FEFF}//;
      s{/\*.*?\*/}{}gs;
      s{--[^\r\n]*}{}g;
    ' "$file" 2>/dev/null | \
    sed -E 's/[[:space:];]+//g'
  )

  [ -n "$cleaned" ]
}

# Get all unique prefixes (e.g., 000001, always 6 digits) from .up.sql files.
prefixes=($(ls "$migrations_path"/*.up.sql 2>/dev/null | \
    sed -E 's/.*\/([0-9]{6})_.*\.up\.sql/\1/' | sort))

# Check if no prefixes were found.
if [ ${#prefixes[@]} -eq 0 ]; then
  echo "No .up.sql migration files found in $migrations_path."
  exit 1
fi

# Iterate over prefixes to ensure that there are no gaps and that each prefix
# has a corresponding .down.sql file. Because the prefixes are sorted, and the
# index starts at 0, we expect each prefix to be the index plus one.
for i in "${!prefixes[@]}"; do
  expected_prefix=$(printf "%06d" $((i+1)))

  if [ "${prefixes[$i]}" != "$expected_prefix" ]; then
    echo "Error: Missing migration with prefix $expected_prefix."
    exit 1
  fi

  # Find the corresponding .down.sql file.
  base_filename=$(ls "$migrations_path/${prefixes[$i]}"_*.up.sql | \
      sed -E 's/\.up\.sql//')

  # Error if the .up.sql is an SQL migration, but we're missing the
  # corresponding .down.sql. This doesn't apply if the .up.sql file is a
  # programmatic migration.
  if is_sql_migration "$base_filename.up.sql" && \
      [ ! -f "$base_filename.down.sql" ]; then
    echo "Error: Missing .down.sql file for migration $expected_prefix."
    exit 1
  fi
done

echo "All migration files are present and properly numbered."