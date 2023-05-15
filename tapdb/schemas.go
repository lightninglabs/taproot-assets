package tapdb

import (
	"embed"
	_ "embed"
)

//go:embed sqlc/migrations/*.up.sql
var sqlSchemas embed.FS
