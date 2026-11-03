package audit

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"culinux/pkg/audit/helpers"
	"culinux/pkg/config"

	"github.com/stretchr/testify/require"
)

func TestRunTasks_StopsPeersAndPreservesFailure(t *testing.T) {
	cause := errors.New("map setup failed")
	started, stopped := make(chan struct{}), make(chan struct{})
	err := runTasks(context.Background(), []auditTask{
		{"peer", func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(stopped)
			return ctx.Err()
		}},
		{"network", func(context.Context) error { <-started; return cause }},
	})
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "network")
	select {
	case <-stopped:
	default:
		t.Fatal("peer was not stopped before returning")
	}
}

func TestConfiguredTasks_OnlyEnabledModules(t *testing.T) {
	conf := config.DefaultConfig()
	require.Empty(t, configuredTasks(conf))
	conf.RestrictedNetworkConfig.Enable = true
	tasks := configuredTasks(conf)
	require.Len(t, tasks, 1)
	require.Equal(t, "network", tasks[0].name)
}

func TestRunTasks_ReadinessWaitsForEveryModule(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fast, release, ready, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- runTasksWithOptions(ctx, []auditTask{
			{"fast", func(ctx context.Context) error {
				helpers.ReportReady(ctx)
				helpers.ReportReady(ctx)
				close(fast)
				<-ctx.Done()
				return nil
			}},
			{"slow", func(ctx context.Context) error {
				<-release
				helpers.ReportReady(ctx)
				<-ctx.Done()
				return nil
			}},
		}, runOptions{ready: func(context.Context) error { close(ready); return nil }})
	}()
	<-fast
	select {
	case <-ready:
		t.Fatal("ready before slow module")
	default:
	}
	close(release)
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("readiness not reported")
	}
	cancel()
	require.NoError(t, <-done)
}

func TestRunTasks_StartupTimeoutCancelsInitialization(t *testing.T) {
	stopped := make(chan struct{})
	err := runTasksWithOptions(context.Background(), []auditTask{{"blocked", func(ctx context.Context) error {
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	}}}, runOptions{startupTimeout: 10 * time.Millisecond, ready: func(context.Context) error { t.Error("unexpected readiness"); return nil }})
	require.ErrorContains(t, err, "startup timeout")
	<-stopped
}

func TestRunTasks_ShutdownBudgetNamesStuckModule(t *testing.T) {
	cause := errors.New("initialization failed")
	started, release, returned := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	defer close(release)
	go func() {
		returned <- runTasksWithOptions(context.Background(), []auditTask{
			{"stuck", func(context.Context) error { close(started); <-release; return nil }},
			{"failing", func(context.Context) error { <-started; return cause }},
		}, runOptions{shutdownTimeout: 10 * time.Millisecond})
	}()
	select {
	case err := <-returned:
		require.ErrorContains(t, err, "still running: stuck")
		require.ErrorIs(t, err, cause)
	case <-time.After(time.Second):
		t.Fatal("shutdown exceeded its budget")
	}
}

func TestRunTasks_StartupFailureCleansAcquiredResourcesInReverse(t *testing.T) {
	acquired := make(chan struct{})
	var order []int
	err := runTasks(context.Background(), []auditTask{
		{"first", func(ctx context.Context) error {
			defer helpers.Own(ctx, func() { order = append(order, 1) })()
			close(acquired)
			<-ctx.Done()
			return nil
		}},
		{"second", func(ctx context.Context) error {
			<-acquired
			defer helpers.Own(ctx, func() { order = append(order, 2) })()
			return errors.New("prepare failed")
		}},
	})
	require.ErrorContains(t, err, "prepare failed")
	require.Equal(t, []int{2, 1}, order)
}

func TestRunTasks_PreservesSimultaneousFailures(t *testing.T) {
	var started sync.WaitGroup
	started.Add(2)
	first := errors.New("first failure")
	second := &os.PathError{Op: "open", Path: "missing", Err: os.ErrNotExist}
	err := runTasks(context.Background(), []auditTask{
		{"first", func(context.Context) error { started.Done(); started.Wait(); return first }},
		{"second", func(context.Context) error { started.Done(); started.Wait(); return second }},
	})
	require.ErrorIs(t, err, first)
	require.ErrorIs(t, err, os.ErrNotExist)
	var pathError *os.PathError
	require.ErrorAs(t, err, &pathError)
	require.Same(t, second, pathError)
	require.ErrorContains(t, err, "first audit")
	require.ErrorContains(t, err, "second audit")
}

func TestRunTasks_ExternalCancellationAndDeadlineAreDistinct(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	task := auditTask{"unused", func(context.Context) error { t.Error("started after parent stopped"); return nil }}
	require.NoError(t, runTasks(canceled, []auditTask{task}))
	require.ErrorIs(t, runTasks(expired, []auditTask{task}), context.DeadlineExceeded)
	ctx, done := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer done()
	err := runTasks(ctx, []auditTask{{"peer", func(ctx context.Context) error {
		helpers.ReportReady(ctx)
		<-ctx.Done()
		return ctx.Err()
	}}})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRunTasks_PanicCancelsPeersAndReleasesResources(t *testing.T) {
	cause := errors.New("panic cause")
	started := make(chan struct{})
	cleaned := false
	err := runTasks(context.Background(), []auditTask{
		{"peer", func(ctx context.Context) error { close(started); <-ctx.Done(); return nil }},
		{"broken", func(ctx context.Context) error {
			<-started
			defer helpers.Own(ctx, func() { cleaned = true })()
			panic(cause)
		}},
	})
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "broken")
	require.True(t, cleaned)
}

func TestCallAuditTask_PanicNilIsStillFailure(t *testing.T) {
	err, panicked := callAuditTask(context.Background(), func(context.Context) error { panic(nil) })
	require.Error(t, err)
	require.True(t, panicked)
}

func TestRunTasks_NotificationFailureStopsReadyWorkers(t *testing.T) {
	cause := errors.New("service manager unavailable")
	stopped := false
	options := defaultRunOptions()
	WithReadyNotification(func(context.Context) error { return cause })(&options)
	err := runTasksWithOptions(context.Background(), []auditTask{{"peer", func(ctx context.Context) error {
		helpers.ReportReady(ctx)
		<-ctx.Done()
		stopped = true
		return nil
	}}}, options)
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "readiness notification")
	require.True(t, stopped)
}
