package arp

import (
	"net"
	"testing"
)

var (
	ip1  = net.ParseIP("192.168.0.1").To4()
	ip2  = net.ParseIP("192.168.0.2").To4()
	ip3  = net.ParseIP("192.168.0.3").To4()
	mac1 = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2 = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3 = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x03}
)

func Test_AddSimple(t *testing.T) {

	h := &Handler{}
	MACEntry := h.update(StateNormal, mac1, ip1)

	if MACEntry != h.findByMAC(mac1) || MACEntry != h.findByIP(ip1) {
		t.Error("expected cannot find MACEntry ", mac1.String(), ip1)
	}
}

func Test_AddMany(t *testing.T) {

	h := &Handler{table: make([]*MACEntry, 0, 256)}

	MACEntry := h.update(StateNormal, mac1, ip1)
	MACEntry2 := h.update(StateNormal, mac2, ip2)
	MACEntry3 := h.update(StateNormal, mac3, ip3)

	if len(h.table) != 3 || MACEntry3 != h.findByMAC(mac3) || MACEntry3 != h.findByIP(ip3) {
		h.PrintTable()
		t.Error("expected cannot find MACEntry ", len(h.table), mac3.String(), ip3)
	}
	if len(h.table) != 3 || MACEntry2 != h.findByMAC(mac2) || MACEntry2 != h.findByIP(ip2) {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}

	h.table[1] = nil

	if len(h.table) != 3 || MACEntry3 != h.findByMAC(mac3) || MACEntry3 != h.findByIP(ip3) {
		t.Error("expected cannot find MACEntry ", mac3.String(), ip3)
	}

	if len(h.table) != 3 || h.findByMAC(mac2) != nil || h.findByIP(ip2) != nil {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}

	h.update(StateNormal, mac2, ip2)
	if len(h.table) != 3 || MACEntry != h.findByMAC(mac1) || MACEntry != h.findByIP(ip1) {
		h.PrintTable()
		t.Error("expected cannot find MACEntry ", len(h.table), mac1.String(), ip1)
	}
}
func Test_DeleteVirtualMAC(t *testing.T) {

	h := &Handler{table: make([]*MACEntry, 0, 256)}
	h.update(StateNormal, mac1, ip1)
	MACEntry2 := h.update(StateVirtualHost, mac2, ip2)
	h.update(StateNormal, mac3, ip3)

	if len(h.table) != 3 || MACEntry2 != h.findByMAC(mac2) || MACEntry2 != h.FindVirtualIP(ip2) {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}
	h.deleteVirtualMAC(MACEntry2)

	if len(h.table) != 3 || h.findByMAC(mac2) != nil || h.findByIP(ip2) != nil {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}

	MACEntry2 = h.update(StateNormal, mac2, ip2)
	if len(h.table) != 3 || MACEntry2 != h.findByMAC(mac2) || MACEntry2 != h.findByIP(ip2) {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}
}
