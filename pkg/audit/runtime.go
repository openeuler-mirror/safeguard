package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"culinux/pkg/audit/fileaccess"
	"culinux/pkg/audit/helpers"
	"culinux/pkg/audit/mount"
	"culinux/pkg/audit/network"
	"culinux/pkg/audit/process"
	"culinux/pkg/config"
	log "culinux/pkg/log"
)

type auditTask struct {
	name string
	run  func(context.Context) error
}

func configuredTasks(conf *config.Config) []auditTask {
	var tasks []auditTask
	for _, module := range []struct {
		name    string
		enabled bool
		run     func(context.Context, *sync.WaitGroup, *config.Config) error
	}{
		{"files", conf.RestrictedFileAccessConfig.Enable, fileaccess.RunAudit},
		{"network", conf.RestrictedNetworkConfig.Enable, network.RunAudit},
		{"process", conf.RestrictedProcessConfig.Enable, process.RunAudit},
		{"mount", conf.RestrictedMountConfig.Enable, mount.RunAudit},
	} {
		if !module.enabled {
			continue
		}
		run := module.run
		tasks = append(tasks, auditTask{module.name, func(ctx context.Context) error {
			var done sync.WaitGroup
			done.Add(1)
			return run(ctx, &done, conf)
		}})
	}
	return tasks
}

type runOptions struct{ ready func() }

func runTasks(parent context.Context, tasks []auditTask) error {
	return runTasksWithOptions(parent, tasks, runOptions{ready: func() {
		log.Info("All configured audit modules started.")
	}})
}

func runTasksWithOptions(parent context.Context, tasks []auditTask, options runOptions) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	results := make(chan error, len(tasks))
	ready := make(chan struct{}, len(tasks))
	pending := len(tasks)
	for _, task := range tasks {
		task := task
		go func() {
			taskContext := helpers.WithReadiness(ctx, func() { ready <- struct{}{} })
			err := task.run(taskContext)
			if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
				err = fmt.Errorf("%s audit: %w", task.name, err)
			} else {
				err = nil
			}
			results <- err
		}()
	}
	var failure error
	for remaining := len(tasks); remaining > 0; {
		select {
		case <-ready:
			pending--
			if pending == 0 && ctx.Err() == nil && options.ready != nil {
				options.ready()
			}
		case err := <-results:
			remaining--
			if err != nil && failure == nil {
				failure = err
				cancel()
			}
		}
	}
	return failure
}
