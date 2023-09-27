package audit

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"

	"culinux/pkg/audit/fileaccess"
	"culinux/pkg/audit/mount"
	"culinux/pkg/audit/network"
	"culinux/pkg/audit/process"
	"culinux/pkg/config"
	log "culinux/pkg/log"
	"culinux/pkg/utils"

	"github.com/urfave/cli/v2"
)

var (
	configFlag = cli.StringFlag{
		Name:    "config",
		Value:   "safeguard.yaml",
		Usage:   "config file path",
		EnvVars: []string{"SG_CONFIG_PATH"},
	}
)

func NewApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "safeguard"
	app.Version = "0.0.10"
	app.Usage = "..."

	flags := []cli.Flag{&configFlag}

	app.Flags = flags

	app.Action = func(c *cli.Context) error {
		path := c.String("config")
		conf, err := config.NewConfig(path)
		if err != nil {
			log.Error(err)
			return nil
		}
		if !utils.AmIRootUser() {
			return errors.New("Must be run as root user")
		}

		log.SetFormatter(conf.Log.Format)
		log.SetOutput(conf.Log.Output)
		log.SetRotation(conf.Log.Output, conf.Log.MaxSize, conf.Log.MaxAge)
		log.SetLabel(conf.Log.Labels)
		log.SetLevel(conf.Log.Level)

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(4)

		go fileaccess.RunAudit(ctx, &wg, conf)
		go network.RunAudit(ctx, &wg, conf)
		go process.RunAudit(ctx, &wg, conf)
		go mount.RunAudit(ctx, &wg, conf)

		wg.Wait()
		log.Info("Terminate all audit.")
		return nil
	}

	if os.Getenv("SKIP_COMPATIBLE_CHECK") == "" {
		err := utils.IsCompatible()
		if err != nil {
			log.Error(err)
		}
	}

	return app
}
