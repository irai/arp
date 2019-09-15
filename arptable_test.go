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
	entry := h.arpTableAppendLocked(StateNormal, mac1, ip1)

	if entry != h.FindMAC(mac1) || entry != h.FindIP(ip1) {
		t.Error("expected cannot find entry ", mac1.String(), ip1)
	}
}

func Test_AddMany(t *testing.T) {

	h := &Handler{table: make([]*Entry, 0, 256)}

	entry := h.arpTableAppendLocked(StateNormal, mac1, ip1)
	entry2 := h.arpTableAppendLocked(StateNormal, mac2, ip2)
	entry3 := h.arpTableAppendLocked(StateNormal, mac3, ip3)

	if len(h.table) != 3 || entry3 != h.FindMAC(mac3) || entry3 != h.FindIP(ip3) {
		h.PrintTable()
		t.Error("expected cannot find entry ", len(h.table), mac3.String(), ip3)
	}
	if len(h.table) != 3 || entry2 != h.FindMAC(mac2) || entry2 != h.FindIP(ip2) {
		t.Error("expected cannot find entry ", mac2.String(), ip2)
	}

	h.table[1] = nil

	if len(h.table) != 3 || entry3 != h.FindMAC(mac3) || entry3 != h.FindIP(ip3) {
		t.Error("expected cannot find entry ", mac3.String(), ip3)
	}

	if len(h.table) != 3 || h.FindMAC(mac2) != nil || h.FindIP(ip2) != nil {
		t.Error("expected cannot find entry ", mac2.String(), ip2)
	}

	h.arpTableAppendLocked(StateNormal, mac2, ip2)
	if len(h.table) != 3 || entry != h.FindMAC(mac1) || entry != h.FindIP(ip1) {
		h.PrintTable()
		t.Error("expected cannot find entry ", len(h.table), mac1.String(), ip1)
	}
}
func Test_DeleteVirtualMAC(t *testing.T) {

	h := &Handler{table: make([]*Entry, 0, 256)}
	h.arpTableAppendLocked(StateNormal, mac1, ip1)
	entry2 := h.arpTableAppendLocked(StateVirtualHost, mac2, ip2)
	h.arpTableAppendLocked(StateNormal, mac3, ip3)

	if len(h.table) != 3 || entry2 != h.FindMAC(mac2) || entry2 != h.FindVirtualIP(ip2) {
		t.Error("expected cannot find entry ", mac2.String(), ip2)
	}
	h.deleteVirtualMAC(entry2)

	if len(h.table) != 3 || h.FindMAC(mac2) != nil || h.FindIP(ip2) != nil {
		t.Error("expected cannot find entry ", mac2.String(), ip2)
	}

	entry2 = h.arpTableAppendLocked(StateNormal, mac2, ip2)
	if len(h.table) != 3 || entry2 != h.FindMAC(mac2) || entry2 != h.FindIP(ip2) {
		t.Error("expected cannot find entry ", mac2.String(), ip2)
	}
}
