package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"culinux/pkg/controller/model"
)

func readPasswdAccounts(path string) ([]model.Account, []uint, []uint, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer file.Close()

	accounts := []model.Account{}
	uids := []uint{}
	gids := []uint{}
	warnings := []string{}

	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if strings.TrimSpace(text) == "" || strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		fields := strings.Split(text, ":")
		if len(fields) < 7 || fields[0] == "" {
			warnings = append(warnings, fmt.Sprintf("%s:%d: malformed passwd entry", path, line))
			continue
		}
		uid64, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s:%d: malformed passwd entry", path, line))
			continue
		}
		gid64, err := strconv.ParseUint(fields[3], 10, 32)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s:%d: malformed passwd entry", path, line))
			continue
		}
		account := model.Account{
			Username: fields[0],
			UID:      uint(uid64),
			GID:      uint(gid64),
			HomeDir:  fields[5],
			Shell:    fields[6],
		}
		accounts = append(accounts, account)
		uids = append(uids, account.UID)
		gids = append(gids, account.GID)
	}

	if err := scanner.Err(); err != nil {
		return accounts, uids, gids, warnings, fmt.Errorf("scan passwd %q at line %d: %w", path, line+1, err)
	}
	return accounts, uids, gids, warnings, nil
}
