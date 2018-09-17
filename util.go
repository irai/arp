package arp

import "net"

func DupIP(srcIP net.IP) net.IP {
	ip := make(net.IP, len(srcIP))
	copy(ip, srcIP)
	return ip
}

func DupMAC(srcMAC net.HardwareAddr) net.HardwareAddr {
	mac := make(net.HardwareAddr, len(srcMAC))
	copy(mac, srcMAC)
	return mac
}
