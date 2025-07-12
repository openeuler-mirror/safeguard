//go:build integration
// +build integration

package process

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"testing"

	"safeguard/pkg/config"

	"github.com/stretchr/testify/assert"
)

func TestAudit_DenyAccess(t *testing.T) {
	t.Skip("This test is not applicable for process audit")
}

func TestAudit_Container(t *testing.T) {
	t.Skip("This test is not applicable for process audit")
}

func TestRunAudit_Conf(t *testing.T) {
	config := config.DefaultConfig()
	config.RestrictedProcessConfig.Enable = false
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	assert.Nil(t, StartProcessAudit(ctx, &wg, config))
}

type TestAuditController struct {
	controller ProcessController
	cmd        *exec.Cmd
}

func runAuditWithOnce(conf *config.Config, execCmd []string, eventsChannel chan []byte) TestAuditController {
	ctrl := createController(conf)
	ctrl.Attach()
	lostChannel := make(chan uint64)
	ctrl.Start(eventsChannel, lostChannel)

	cmd := exec.Command(execCmd[0], execCmd[1:]...)
	err := cmd.Start()

	if err != nil {
		panic(err)
	}

	cmd.Wait()

	return TestAuditController{
		controller: ctrl,
		cmd:        cmd,
	}
}
