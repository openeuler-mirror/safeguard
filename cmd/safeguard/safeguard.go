package main

import (
	"os"

	"culinux/pkg/audit"

	log "github.com/sirupsen/logrus"
)

var (
	version = "dev"
)

func main() {
	app := audit.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
