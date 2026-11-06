package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"culinux/pkg/controller/model"
)

func readProcProcesses(procRoot string) ([]model.RunningProcess, []uint, []uint, []string, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	processes := []model.RunningProcess{}
	uids := []uint{}
	gids := []uint{}
	executables := []string{}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 22)
		if err != nil || pid == 0 || strconv.FormatUint(pid, 10) != entry.Name() {
			continue
		}

		base := filepath.Join(procRoot, entry.Name())
		commandBytes, err := os.ReadFile(filepath.Join(base, "comm"))
		if err != nil {
			if processGone(err) {
				continue
			}
			return nil, nil, nil, nil, fmt.Errorf("read process %d comm: %w", pid, err)
		}
		statusBytes, err := os.ReadFile(filepath.Join(base, "status"))
		if err != nil {
			if processGone(err) {
				continue
			}
			return nil, nil, nil, nil, fmt.Errorf("read process %d status: %w", pid, err)
		}

		if !validStatusIDs(string(statusBytes)) {
			continue
		}
		uid, gid := parseStatusIDs(string(statusBytes))
		executable, _ := os.Readlink(filepath.Join(base, "exe"))
		if strings.HasSuffix(executable, " (deleted)") {
			executable = ""
		}

		processes = append(processes, model.RunningProcess{
			PID:        int(pid),
			Command:    strings.TrimSuffix(string(commandBytes), "\n"),
			Executable: executable,
			UID:        uid,
			GID:        gid,
		})
		uids = append(uids, uid)
		gids = append(gids, gid)
		if executable != "" {
			executables = append(executables, executable)
		}
	}

	return processes, uids, gids, executables, nil
}

func parseStatusIDs(content string) (uint, uint) {
	lines := strings.Split(content, "\n")
	var uid uint
	var gid uint

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				uid = uint(value)
			}
		case "Gid:":
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				gid = uint(value)
			}
		}
	}

	return uid, gid
}

func validStatusIDs(content string) bool {
	seen := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "Uid:" && fields[0] != "Gid:") {
			continue
		}
		if len(fields) < 2 || seen[fields[0]] {
			return false
		}
		if _, err := strconv.ParseUint(fields[1], 10, 32); err != nil {
			return false
		}
		seen[fields[0]] = true
	}
	return seen["Uid:"] && seen["Gid:"]
}

func processGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}
