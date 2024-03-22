package tapdb

import (
	"embed"
	_ "embed"
)

//go:embed sqlc/migrations/*.*.sql
var sqlSchemas embed.FS
