package commands

import (
	"fmt"
	"os"
	"strings"

	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/urfave/cli"
	"golang.org/x/exp/maps"
)

const (
	backupModeName   = "mode"
	backupOutputName = "output_file"
	backupFileName   = "backup_file"
)

// nolint:lll
var backupModeMap = map[string]wrpc.BackupMode{
	"raw":        wrpc.BackupMode_RAW,
	"compact":    wrpc.BackupMode_COMPACT,
	"optimistic": wrpc.BackupMode_OPTIMISTIC,
}

var backupCommand = cli.Command{
	Name:      "backup",
	ShortName: "bk",
	Usage:     "Export or import wallet asset backups.",
	Subcommands: []cli.Command{
		exportBackupCommand,
		importBackupCommand,
	},
}

var exportBackupCommand = cli.Command{
	Name:      "export",
	ShortName: "e",
	Usage:     "export a wallet asset backup",
	Description: `
	Export a backup of all active assets in the wallet. The backup can be
	used to restore assets on a new node using the import command.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: backupModeName,
			Usage: "the backup mode to use; possible values " +
				"are: " + strings.Join(
				maps.Keys(backupModeMap), ", ",
			),
			Value: "compact",
		},
		cli.StringFlag{
			Name: backupOutputName,
			Usage: "the file path to write the backup to; " +
				"use the dash character (-) to write " +
				"to stdout",
		},
	},
	Action: exportBackup,
}

func exportBackup(ctx *cli.Context) error {
	if !ctx.IsSet(backupOutputName) {
		return cli.ShowSubcommandHelp(ctx)
	}

	modeStr := ctx.String(backupModeName)
	mode, ok := backupModeMap[modeStr]
	if !ok {
		return fmt.Errorf("unknown backup mode '%s'; valid modes "+
			"are: %s", modeStr,
			strings.Join(maps.Keys(backupModeMap), ", "))
	}

	ctxc := getContext()
	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	resp, err := client.ExportAssetWalletBackup(
		ctxc, &wrpc.ExportAssetWalletBackupRequest{
			Mode: mode,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to export backup: %w", err)
	}

	filePath := lncfg.CleanAndExpandPath(ctx.String(backupOutputName))
	if err := writeToFile(filePath, resp.Backup); err != nil {
		return fmt.Errorf("unable to write backup file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Backup exported successfully: mode=%s "+
		"size=%d path=%s\n", modeStr, len(resp.Backup), filePath)

	return nil
}

var importBackupCommand = cli.Command{
	Name:      "import",
	ShortName: "i",
	Usage:     "import assets from a wallet backup",
	Description: `
	Import assets from a backup blob that was previously created using
	the export command. This can be used to restore assets on a new node.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: backupFileName,
			Usage: "the file path to read the backup from; " +
				"use the dash character (-) to read " +
				"from stdin",
		},
	},
	Action: importBackup,
}

func importBackup(ctx *cli.Context) error {
	if !ctx.IsSet(backupFileName) {
		return cli.ShowSubcommandHelp(ctx)
	}

	filePath := lncfg.CleanAndExpandPath(ctx.String(backupFileName))
	backupData, err := readFile(filePath)
	if err != nil {
		return fmt.Errorf("unable to read backup file: %w", err)
	}

	ctxc := getContext()
	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	resp, err := client.ImportAssetsFromBackup(
		ctxc, &wrpc.ImportAssetsFromBackupRequest{
			Backup: backupData,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to import backup: %w", err)
	}

	printRespJSON(resp)
	return nil
}
