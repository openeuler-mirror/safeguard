package audit

import (
	"context"
	"errors"
	"sync"
	"testing"

	"culinux/pkg/audit/fileaccess"
	"culinux/pkg/audit/mount"
	"culinux/pkg/audit/network"
	"culinux/pkg/audit/process"
	"culinux/pkg/config"
)

func TestCanceledModuleNeverLoadsBPF(t *testing.T) {
	conf := config.DefaultConfig()
	conf.RestrictedFileAccessConfig.Enable = true
	conf.RestrictedMountConfig.Enable = true
	conf.RestrictedNetworkConfig.Enable = true
	conf.RestrictedProcessConfig.Enable = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, run := range []func(context.Context, *sync.WaitGroup, *config.Config) error{fileaccess.RunAudit, mount.RunAudit, network.RunAudit, process.RunAudit} {
		var workers sync.WaitGroup
		workers.Add(1)
		if err := run(ctx, &workers, conf); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected canceled stage without BPF access: %v", err)
		}
		workers.Wait()
	}
}
