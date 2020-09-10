package arp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
)

// loadARPProcTable read arp entries from linux proc file
//
// /proc/net/arp format:
//   IP address       HW type     Flags       HW address            Mask     Device
//   192.168.0.1      0x1         0x2         20:0c:c8:23:f7:1a     *        eth0
//   192.168.0.4      0x1         0x2         4c:bb:58:f4:b2:d7     *        eth0
//   192.168.0.5      0x1         0x2         84:b1:53:ea:1f:40     *        eth0
//
func loadARPProcTable() (table *arpTable, err error) {
	const name = "/proc/net/arp"
	table = newARPTable()

	file, err := os.Open(name)
	if err != nil {
		return table, fmt.Errorf("failed to open proc file=%s: %w ", name, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		tokens := strings.Fields(scanner.Text())
		if len(tokens) < 4 {
			continue
		}
		ip := net.ParseIP(tokens[0]).To4()
		if ip.IsUnspecified() {
			continue
		}
		mac, err := net.ParseMAC(tokens[3])
		if err != nil || bytes.Equal(mac, net.HardwareAddr{0, 0, 0, 0, 0, 0}) || bytes.Equal(mac, net.HardwareAddr{}) {
			continue
		}
		entry, _ := table.upsert(StateNormal, mac, ip)
		entry.Online = true
	}

	return table, nil
}
