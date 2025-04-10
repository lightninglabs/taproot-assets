package main

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	_ "modernc.org/sqlite" // Register the pure-Go SQLite driver.
)

func main() {
	// Open an in-memory SQLite database.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		log.Fatalf("failed to open in-memory db: %v", err)
	}
	defer db.Close()

	migrationDir := "tapdb/sqlc/migrations"
	files, err := os.ReadDir(migrationDir)
	if err != nil {
		log.Fatalf("failed to read migration dir: %v", err)
	}

	var upFiles []string
	upRegex := regexp.MustCompile(`\.up\.sql$`)
	for _, f := range files {
		if !f.IsDir() && upRegex.MatchString(f.Name()) {
			upFiles = append(upFiles, f.Name())
		}
	}
	sort.Strings(upFiles)

	// Execute each up migration in order.
	for _, fname := range upFiles {
		path := filepath.Join(migrationDir, fname)
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("failed to read file %s: %v", fname, err)
		}
		_, err = db.Exec(string(data))
		if err != nil {
			log.Fatalf("error executing migration %s: %v", fname,
				err)
		}
	}

	// ---------------------------------------------------------------------
	// Retrieve final database schema from sqlite_master.
	//
	// SQLite automatically maintains a special table called sqlite_master,
	// which holds metadata about all objects inside the database, such as
	// tables, views, indexes, and triggers. Each row in this table
	// represents an object, with columns such as "type" (the kind of
	// object), "name" (the object's name), and "sql" (the SQL DDL statement
	// that created it).
	//
	// In our case, after running all the migration files on an in‑memory
	// database, we execute the following query to extract only the schema
	// definitions for tables and views. Ordering by name ensures the output
	// is stable across runs.
	//
	// This way, we can consolidate and export the complete database schema
	// as it stands after all migrations have been applied.
	//
	// We filter our where sql is NOT NULL, as for the internal sqlite
	// creates, the sql column will be NULL.
	// ---------------------------------------------------------------------
	rows, err := db.Query(`
		SELECT type, name, sql FROM sqlite_master 
		WHERE type IN ('table','view', 'index') AND sql IS NOT NULL 
		ORDER BY name`,
	)
	if err != nil {
		log.Fatalf("failed to query schema: %v", err)
	}
	defer rows.Close()

	var generatedSchema string
	for rows.Next() {
		var typ, name, sqlDef string
		if err := rows.Scan(&typ, &name, &sqlDef); err != nil {
			log.Fatalf("error scanning row: %v", err)
		}

		// Append the retrieved CREATE statement. We add a semicolon and
		// a couple of line breaks to clearly separate each object's
		// definition.
		generatedSchema += sqlDef + ";\n\n"
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("error iterating rows: %v", err)
	}

	// Finally, we'll write out the new schema, taking care to ensure that
	// that output dir exists.
	outDir := "tapdb/sqlc/schemas"
	if err = os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("failed to create schema output dir: %v", err)
	}
	outFile := filepath.Join(outDir, "generated_schema.sql")
	err = os.WriteFile(outFile, []byte(generatedSchema), 0644)
	if err != nil {
		log.Fatalf("failed to write final schema file: %v", err)
	}
	log.Printf("Final consolidated schema written to %s", outFile)
}
