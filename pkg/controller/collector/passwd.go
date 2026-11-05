package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"culinux/pkg/controller/model"
)

func readPasswdAccounts(path string) ([]model.Account, []uint, []uint, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close()

	accounts := []model.Account{}
	uids := []uint{}
	gids := []uint{}

	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 7 || fields[0] == "" {
			continue
		}
		uid64, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		gid64, err := strconv.ParseUint(fields[3], 10, 32)
		if err != nil {
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
		return accounts, uids, gids, fmt.Errorf("scan passwd %q at line %d: %w", path, line+1, err)
	}
	return accounts, uids, gids, nil
}
