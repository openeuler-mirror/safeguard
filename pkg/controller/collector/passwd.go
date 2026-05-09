package collector

import (
	"bufio"
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
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		uid64, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			continue
		}
		gid64, err := strconv.ParseUint(fields[3], 10, 64)
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

	return accounts, uids, gids, scanner.Err()
}
