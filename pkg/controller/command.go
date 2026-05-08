package controller

import "github.com/urfave/cli/v2"

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:  "controller",
		Usage: "Generate whitelist configuration from host snapshot",
		Subcommands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Collect host data and generate whitelist configuration",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "output",
						Value: "demo-whitelist.yaml",
						Usage: "Output path for whitelist YAML config",
					},
					&cli.StringFlag{
						Name:  "report",
						Value: "demo-whitelist-report.json",
						Usage: "Output path for whitelist JSON report",
					},
					&cli.StringFlag{
						Name:  "mode",
						Value: "monitor",
						Usage: "Operation mode: monitor or block",
					},
				},
				Action: func(c *cli.Context) error {
					return nil // TODO: implement
				},
			},
		},
	}
}
