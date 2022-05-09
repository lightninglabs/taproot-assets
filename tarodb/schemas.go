package tarodb

import (
	"embed"
	_ "embed"
)

//go:embed sqlite/migrations/*.up.sql
var sqlSchemas embed.FS
