package controller

import "github.com/urfave/cli/v2"

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:  "controller",
		Usage: "Generate whitelist configuration from host snapshot",
		UsageText: `safeguard controller generate [options]

EXAMPLES:
   # Generate whitelist config with block mode
   safeguard controller generate --output /etc/safeguard/whitelist.yaml --mode block

   # Generate whitelist config with monitor mode (default, only log)
   safeguard controller generate --output whitelist.yaml --report report.json

   # Generate and run immediately
   safeguard controller generate --output /etc/safeguard/whitelist.yaml && sudo safeguard --config /etc/safeguard/whitelist.yaml`,
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
						Usage: "Operation mode: 'monitor' (log only) or 'block' (enforce whitelist)",
					},
				},
				Action: func(c *cli.Context) error {
					service := NewService()
					return service.Generate(GenerateOptions{
						Mode:       c.String("mode"),
						OutputPath: c.String("output"),
						ReportPath: c.String("report"),
					})
				},
			},
		},
	}
}
