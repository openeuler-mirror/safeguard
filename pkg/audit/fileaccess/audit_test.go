//go:build integration
// +build integration

package fileaccess

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"testing"
	"time"

	"safeguard/pkg/audit/helpers"
	"safeguard/pkg/config"

	"github.com/stretchr/testify/assert"
)

func TestAudit_DenyAccess(t *testing.T) {
	beBlockedPath := "/etc/hosts"
	timeout := time.After(10 * time.Second)
	done := make(chan bool)
	conf := config.DefaultConfig()
	conf.RestrictedFileAccessConfig.Mode = "block"
	conf.RestrictedFileAccessConfig.Target = "host"
	conf.RestrictedFileAccessConfig.Deny = []string{beBlockedPath}
	eventsChannel := make(chan []byte)
	auditController := runAuditWithOnce(conf, []string{"cat", beBlockedPath}, eventsChannel)
	defer auditController.controller.Stop()
	defer auditController.controller.bpfModule.Close()

	go func() {
		for {
			eventBytes := <-eventsChannel

			event, err := decodeEvent(eventBytes)
			assert.Nil(t, err)

			if beBlockedPath == convertPathToString(event.Path) {
				assert.Equal(t, int32(-1), event.Ret)
				assert.Equal(t, auditController.cmd.Process.Pid, int(event.PID))
				assert.Equal(t, beBlockedPath, convertPathToString(event.Path))
				done <- true
				break
			}
		}
	}()

	select {
	case <-timeout:
		t.Fatalf("Timeout. %s has not accessed.", beBlockedPath)
	case <-done:
		t.Log("OK")
	}

	err := exec.Command("cat", "/etc/passwd").Run()
	assert.Nil(t, err)
}

func TestAudit_Container(t *testing.T) {
	out, _ := exec.Command("bpftool", "map", "list").Output()
	fmt.Println(string(out))
	beBlockedPath := "/root/.bashrc"
	timeout := time.After(10 * time.Second)
	done := make(chan bool)
	conf := config.DefaultConfig()
	conf.RestrictedFileAccessConfig.Mode = "block"
	conf.RestrictedFileAccessConfig.Target = "container"
	conf.RestrictedFileAccessConfig.Deny = []string{beBlockedPath}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("can not get hostname: %s", err)
	}

	commands := []string{
		"/bin/bash",
		"-c",
		fmt.Sprintf("/usr/bin/docker run --rm ubuntu:latest cat %s", beBlockedPath),
	}
	eventsChannel := make(chan []byte)
	auditController := runAuditWithOnce(conf, commands, eventsChannel)
	defer auditController.controller.Stop()
	defer auditController.controller.bpfModule.Close()

	go func() {
		for {
			eventBytes := <-eventsChannel

			event, err := decodeEvent(eventBytes)
			assert.Nil(t, err)

			if beBlockedPath == convertPathToString(event.Path) {
				assert.Equal(t, int32(-1), event.Ret)
				assert.NotEqual(t, helpers.NodenameToString(event.Nodename), hostname)
				assert.Equal(t, beBlockedPath, convertPathToString(event.Path))
				done <- true
				break
			}
		}
	}()

	select {
	case <-timeout:
		t.Fatalf("Timeout. %s has not accessed.", beBlockedPath)
	case <-done:
		t.Log("OK")
	}
}

func TestRunAudit_Conf(t *testing.T) {
	config := config.DefaultConfig()
	config.RestrictedFileAccessConfig.Enable = false
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	assert.Nil(t, StartFileAccessAudit(ctx, &wg, config))
}

type TestAuditController struct {
	controller FileAccessController
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
