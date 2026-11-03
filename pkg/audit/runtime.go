package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

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

type runOptions struct {
	ready           func()
	startupTimeout  time.Duration
	shutdownTimeout time.Duration
}

func runTasks(parent context.Context, tasks []auditTask) error {
	return runTasksWithOptions(parent, tasks, defaultRunOptions())
}

func defaultRunOptions() runOptions {
	return runOptions{startupTimeout: 30 * time.Second, shutdownTimeout: 10 * time.Second, ready: func() {
		log.Info("All configured audit modules started.")
	}}
}

func runTasksWithOptions(parent context.Context, tasks []auditTask, options runOptions) error {
	if parent.Err() != nil {
		return parentFailure(parent, nil)
	}
	if options.startupTimeout < 0 {
		return fmt.Errorf("startup timeout must not be negative")
	}
	var startup <-chan time.Time
	if options.startupTimeout > 0 {
		timer := time.NewTimer(options.startupTimeout)
		defer timer.Stop()
		startup = timer.C
	}
	if options.shutdownTimeout == 0 {
		options.shutdownTimeout = 10 * time.Second
	}
	if options.shutdownTimeout < 0 {
		return fmt.Errorf("shutdown timeout must not be negative")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ctx, cleanup := helpers.WithCleanup(ctx)
	type taskResult struct {
		name string
		err  error
	}
	results := make(chan taskResult, len(tasks))
	waiting := make(map[string]bool, len(tasks))
	ready := make(chan struct{}, len(tasks))
	pending := len(tasks)
	for _, task := range tasks {
		task := task
		waiting[task.name] = true
		go func() {
			taskContext := helpers.WithReadiness(ctx, func() { ready <- struct{}{} })
			err := task.run(taskContext)
			if err != nil && !(ctx.Err() != nil && errors.Is(err, ctx.Err())) {
				err = fmt.Errorf("%s audit: %w", task.name, err)
			} else {
				err = nil
			}
			results <- taskResult{task.name, err}
		}()
	}
	var failure error
	stopping := ctx.Done()
	var shutdown <-chan time.Time
	var shutdownTimer *time.Timer
	defer func() {
		if shutdownTimer != nil {
			shutdownTimer.Stop()
		}
	}()
	remaining := len(tasks)
	for remaining > 0 {
		select {
		case <-stopping:
			failure = parentFailure(parent, failure)
			stopping = nil
			startup = nil
			shutdownTimer = time.NewTimer(options.shutdownTimeout)
			shutdown = shutdownTimer.C
		case <-shutdown:
			var names []string
			for name := range waiting {
				names = append(names, name)
			}
			sort.Strings(names)
			go func(left int) {
				for i := 0; i < left; i++ {
					<-results
				}
				cleanup()
			}(remaining)
			timeout := fmt.Errorf("audit shutdown timeout; still running: %s", strings.Join(names, ", "))
			if failure != nil {
				return joinFailure(failure, timeout)
			}
			return timeout
		case <-startup:
			failure = fmt.Errorf("audit startup timeout after %s", options.startupTimeout)
			startup = nil
			cancel()
		case <-ready:
			pending--
			if pending == 0 {
				startup = nil
			}
			if pending == 0 && ctx.Err() == nil && options.ready != nil {
				options.ready()
			}
		case result := <-results:
			err := result.err
			delete(waiting, result.name)
			remaining--
			if err != nil {
				failure = joinFailure(failure, err)
				startup = nil
				cancel()
			}
		}
	}
	failure = parentFailure(parent, failure)
	cleaned := make(chan struct{})
	go func() { cleanup(); close(cleaned) }()
	if shutdown == nil {
		shutdownTimer = time.NewTimer(options.shutdownTimeout)
		shutdown = shutdownTimer.C
	}
	select {
	case <-cleaned:
		return failure
	case <-shutdown:
		if failure != nil {
			return joinFailure(failure, fmt.Errorf("audit cleanup timeout"))
		}
		return fmt.Errorf("audit cleanup timeout")
	}
}
