package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		base := filepath.Join(procRoot, entry.Name())
		commandBytes, err := os.ReadFile(filepath.Join(base, "comm"))
		if err != nil {
			continue
		}
		statusBytes, err := os.ReadFile(filepath.Join(base, "status"))
		if err != nil {
			continue
		}

		uid, gid := parseStatusIDs(string(statusBytes))
		executable, _ := os.Readlink(filepath.Join(base, "exe"))

		processes = append(processes, model.RunningProcess{
			PID:        pid,
			Command:    strings.TrimSpace(string(commandBytes)),
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
