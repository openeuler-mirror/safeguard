package audit

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"culinux/pkg/audit/fileaccess"
	"culinux/pkg/audit/mount"
	"culinux/pkg/audit/network"
	"culinux/pkg/audit/process"
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

// NewApp builds the top-level urfave/cli App for safeguard, wiring the
// audit subcommand against the supplied version string. The returned
// App is ready to pass to app.Run; do not reuse it across invocations.
func NewApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "safeguard"
	app.Version = version
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

		// os.Interrupt covers Ctrl-C (SIGINT). SIGTERM is the default
		// signal sent by systemd, container runtimes and process
		// supervisors on shutdown; without it the goroutines below
		// would never observe a graceful shutdown and the BPF programs
		// would be torn down only by SIGTERM's default action.
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(4)

		go fileaccess.RunAudit(ctx, &wg, conf)
		go network.RunAudit(ctx, &wg, conf)
		go process.RunAudit(ctx, &wg, conf)
		go mount.RunAudit(ctx, &wg, conf)

		wg.Wait()
		log.Info("All audit modules stopped.")
		return nil
	}

	return app
}
