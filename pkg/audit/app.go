package audit

import (
	"errors"
	"os"
	"os/signal"
	"time"

	"culinux/pkg/config"
	"culinux/pkg/controller"
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
	app.Usage = "Linux host security audit and whitelist controller based on eBPF/LSM"
	app.UsageText = `safeguard [global options] command [command options]

EXAMPLES:
   # Run with default config
   sudo safeguard --config config/safeguard.yml

   # Run in whitelist mode (block non-whitelisted behaviors)
   sudo safeguard --config /etc/safeguard/safeguard.yaml

   # Generate whitelist config from current host
   safeguard controller generate --output /etc/safeguard/whitelist.yaml --report /var/log/safeguard/report.json --mode block

   # Run in monitor mode (only log, no blocking)
   safeguard controller generate --mode monitor --output whitelist.yaml`
	app.Commands = []*cli.Command{controller.NewCommand()}

	flags := []cli.Flag{&configFlag, &cli.DurationFlag{Name: "startup-timeout", Value: 30 * time.Second, Usage: "Maximum cooperative startup time (0 disables)"}, &cli.DurationFlag{Name: "shutdown-timeout", Value: 10 * time.Second, Usage: "Maximum shutdown waiting time"}}

	app.Flags = flags

	app.Action = func(c *cli.Context) error {
		path := c.String("config")
		conf, err := config.NewConfig(path)
		if err != nil {
			return err
		}
		if !utils.AmIRootUser() {
			return errors.New("Must be run as root user")
		}
		if os.Getenv("SKIP_COMPATIBLE_CHECK") == "" {
			if err := utils.IsCompatible(); err != nil {
				return err
			}
		}

		log.SetFormatter(conf.Log.Format)
		log.SetOutput(conf.Log.Output)
		log.SetRotation(conf.Log.Output, conf.Log.MaxSize, conf.Log.MaxAge)
		log.SetLabel(conf.Log.Labels)
		log.SetLevel(conf.Log.Level)

		ctx, cancel := signal.NotifyContext(c.Context, os.Interrupt)
		defer cancel()

		options := defaultRunOptions()
		options.startupTimeout = c.Duration("startup-timeout")
		options.shutdownTimeout = c.Duration("shutdown-timeout")
		return runTasksWithOptions(ctx, configuredTasks(conf), options)
	}

	return app
}
