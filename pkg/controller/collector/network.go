package collector

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

func collectInterfaceCIDRs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	result := []string{}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			result = append(result, addr.String())
		}
	}
	return result, nil
}

func readProcNetCIDRs(paths []string) ([]string, []string) {
	result := []string{}
	warnings := []string{}

	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s unreadable", path))
			continue
		}

		scanner := bufio.NewScanner(file)
		first := true
		for scanner.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 3 {
				continue
			}
			cidr, err := remoteAddressToCIDR(fields[2])
			if err == nil {
				result = append(result, cidr)
			}
		}
		file.Close()
	}

	return result, warnings
}

func remoteAddressToCIDR(raw string) (string, error) {
	hostPort := strings.Split(raw, ":")
	if len(hostPort) != 2 {
		return "", fmt.Errorf("invalid address: %s", raw)
	}

	decoded, err := hex.DecodeString(hostPort[0])
	if err != nil {
		return "", err
	}

	if len(decoded) == 4 {
		ip := net.IP{decoded[3], decoded[2], decoded[1], decoded[0]}
		return ip.String() + "/32", nil
	}

	if len(decoded) == 16 {
		for i := 0; i < 8; i++ {
			decoded[i], decoded[15-i] = decoded[15-i], decoded[i]
		}
		ip := net.IP(decoded)
		return ip.String() + "/128", nil
	}

	return "", fmt.Errorf("unsupported address length: %d", len(decoded))
}
