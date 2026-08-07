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
			cidr, ok := interfaceAddressToCIDR(addr)
			if !ok {
				continue
			}
			result = append(result, cidr)
		}
	}
	return result, nil
}

func interfaceAddressToCIDR(addr net.Addr) (string, bool) {
	switch value := addr.(type) {
	case *net.IPNet:
		return ipAddressToCIDR(value.IP)
	case *net.IPAddr:
		return ipAddressToCIDR(value.IP)
	default:
		return "", false
	}
}

func ipAddressToCIDR(ip net.IP) (string, bool) {
	if ip == nil || ip.IsUnspecified() {
		return "", false
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return net.IP(ipv4).String() + "/32", true
	}

	if ipv6 := ip.To16(); ipv6 != nil {
		return net.IP(ipv6).String() + "/128", true
	}

	return "", false
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
		cidr, ok := ipAddressToCIDR(ip)
		if !ok {
			return "", fmt.Errorf("unsupported unspecified address: %s", raw)
		}
		return cidr, nil
	}

	if len(decoded) == 16 {
		// Linux /proc/net/tcp6 prints each 32-bit word of the IPv6
		// address via "%08X" against a __be32 (network-order) value,
		// which on a little-endian host emits the bytes in
		// swapped-within-word order. Recover network-byte-order by
		// reversing bytes inside each 4-byte word; the word *order*
		// itself is unchanged. (The previous code did a full 16-byte
		// reverse, which only happened to be correct for addresses
		// with a single non-zero byte at one end — e.g. ::1, and even
		// then only against an equally-wrong fixture.)
		for i := 0; i < 4; i++ {
			base := i * 4
			decoded[base], decoded[base+3] = decoded[base+3], decoded[base]
			decoded[base+1], decoded[base+2] = decoded[base+2], decoded[base+1]
		}
		ip := net.IP(decoded)
		cidr, ok := ipAddressToCIDR(ip)
		if !ok {
			return "", fmt.Errorf("unsupported unspecified address: %s", raw)
		}
		return cidr, nil
	}

	return "", fmt.Errorf("unsupported address length: %d", len(decoded))
}
