package arp

import "net"

func dupIP(srcIP net.IP) net.IP {
	ip := make(net.IP, len(srcIP))
	copy(ip, srcIP)
	return ip.To4()
}

func dupMAC(srcMAC net.HardwareAddr) net.HardwareAddr {
	mac := make(net.HardwareAddr, len(srcMAC))
	copy(mac, srcMAC)
	return mac
}
