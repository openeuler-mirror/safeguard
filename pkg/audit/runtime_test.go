package audit

import (
	"context"
	"errors"
	"testing"

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
