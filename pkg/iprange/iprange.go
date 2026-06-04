package iprange

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Parse accepts a target string in any of these forms:
//   - Single IP:   192.168.1.1
//   - CIDR:        192.168.1.0/24
//   - Range:       192.168.1.1-192.168.1.10
//   - CSV:         192.168.1.1,10.0.0.1
func Parse(target string) ([]net.IP, error) {
	var result []net.IP
	for _, part := range strings.Split(target, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ips, err := parseSingle(part)
		if err != nil {
			return nil, err
		}
		result = append(result, ips...)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no valid IPs parsed from %q", target)
	}
	return result, nil
}

func parseSingle(target string) ([]net.IP, error) {
	if strings.Contains(target, "/") {
		return parseCIDR(target)
	}
	if strings.Contains(target, "-") {
		return parseRange(target)
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", target)
	}
	if v4 := ip.To4(); v4 != nil {
		return []net.IP{v4}, nil
	}
	return []net.IP{ip}, nil
}

func parseCIDR(cidr string) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	var ips []net.IP
	for addr := cloneIP(ipNet.IP); ipNet.Contains(addr); incrementIP(addr) {
		ips = append(ips, cloneIP(addr))
	}

	// Drop network address and broadcast for subnets larger than /31
	ones, bits := ipNet.Mask.Size()
	if bits == 32 && ones < 31 && len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func parseRange(r string) ([]net.IP, error) {
	parts := strings.SplitN(r, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range %q", r)
	}
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IPs in range %q", r)
	}
	start, end = start.To4(), end.To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("only IPv4 ranges supported: %q", r)
	}

	var ips []net.IP
	for addr := cloneIP(start); !after(addr, end); incrementIP(addr) {
		ips = append(ips, cloneIP(addr))
		if len(ips) > 65536 {
			return nil, fmt.Errorf("range %q exceeds 65536 hosts", r)
		}
	}
	return ips, nil
}

// ParsePorts parses a port specification like "1-1024,8080,8443" into a slice of uint16.
func ParsePorts(spec string) ([]uint16, error) {
	seen := make(map[uint16]bool)
	var ports []uint16

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err := strconv.ParseUint(strings.TrimSpace(bounds[0]), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", part, err)
			}
			hi, err := strconv.ParseUint(strings.TrimSpace(bounds[1]), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", part, err)
			}
			if lo > hi {
				return nil, fmt.Errorf("port range %q: low > high", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[uint16(p)] {
					seen[uint16(p)] = true
					ports = append(ports, uint16(p))
				}
			}
		} else {
			p, err := strconv.ParseUint(part, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", part, err)
			}
			if !seen[uint16(p)] {
				seen[uint16(p)] = true
				ports = append(ports, uint16(p))
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports parsed from %q", spec)
	}
	return ports, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func after(a, b net.IP) bool {
	for i := range a {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}
