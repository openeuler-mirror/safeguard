package controller

import "github.com/urfave/cli/v2"

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:  "controller",
		Usage: "Generate whitelist configuration from host snapshot",
	}
}
