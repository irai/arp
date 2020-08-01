package arp

import (
	"net"
	"testing"
)

var (
	ip1  = net.ParseIP("192.168.0.1").To4()
	ip2  = net.ParseIP("192.168.0.2").To4()
	ip3  = net.ParseIP("192.168.0.3").To4()
	ip4  = net.ParseIP("192.168.0.4").To4()
	mac1 = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2 = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3 = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4 = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x04}
)

func testHandler() *Handler {
	h := &Handler{}
	h.table = newARPTable()
	return h
}
func Test_AddSimple(t *testing.T) {

	h := testHandler()
	MACEntry, _ := h.table.upsert(StateNormal, mac1, ip1)

	if MACEntry != h.table.findByMAC(mac1) || MACEntry != h.table.findByIP(ip1) {
		t.Error("expected cannot find MACEntry ", mac1.String(), ip1)
	}
}

func Test_AddMany(t *testing.T) {

	h := testHandler()

	MACEntry, _ := h.table.upsert(StateNormal, mac1, ip1)
	MACEntry2, _ := h.table.upsert(StateNormal, mac2, ip2)
	MACEntry3, _ := h.table.upsert(StateNormal, mac3, ip3)

	h.table.printTable()
	if len(h.table.macTable) != 3 || MACEntry != h.table.findByMAC(mac1) || MACEntry != h.table.findByIP(ip1) {
		h.table.printTable()
		t.Error("expected cannot find MACEntry 3 ", len(h.table.macTable), mac3.String(), ip3)
	}
	if len(h.table.macTable) != 3 || MACEntry3 != h.table.findByMAC(mac3) || MACEntry3 != h.table.findByIP(ip3) {
		h.table.printTable()
		t.Error("expected cannot find MACEntry 3 ", len(h.table.macTable), mac3.String(), ip3)
	}
	if len(h.table.macTable) != 3 || MACEntry2 != h.table.findByMAC(mac2) || MACEntry2 != h.table.findByIP(ip2) {
		t.Error("expected cannot find MACEntry 2 ", mac2.String(), ip2)
	}

	h.table.delete(mac2)

	if len(h.table.macTable) != 2 || MACEntry3 != h.table.findByMAC(mac3) || MACEntry3 != h.table.findByIP(ip3) {
		t.Error("expected cannot find MACEntry 3 second", mac3.String(), ip3)
	}

	if len(h.table.macTable) != 2 || h.table.findByMAC(mac2) != nil || h.table.findByIP(ip2) != nil {
		t.Error("expected cannot find MACEntry 2 second", mac2.String(), ip2)
	}

	MACEntry2, _ = h.table.upsert(StateNormal, mac2, ip2)
	if len(h.table.macTable) != 3 || MACEntry2 != h.table.findByMAC(mac2) || MACEntry2 != h.table.findByIP(ip2) {
		h.table.printTable()
		t.Error("expected cannot find MACEntry 2 third", len(h.table.macTable), mac1.String(), ip1)
	}
}
func Test_Delete(t *testing.T) {

	h := testHandler()
	h.table.upsert(StateNormal, mac1, ip1)
	MACEntry2, _ := h.table.upsert(StateVirtualHost, mac2, nil)
	MACEntry2.updateIP(ip2)
	MACEntry2.updateIP(ip3)
	h.table.upsert(StateNormal, mac3, ip4)

	if len(h.table.macTable) != 3 || MACEntry2 != h.table.findByMAC(mac2) || MACEntry2 != h.table.findVirtualIP(ip2) || MACEntry2 != h.table.findVirtualIP(ip3) {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}
	h.table.delete(MACEntry2.MAC)

	if len(h.table.macTable) != 2 || h.table.findByMAC(mac2) != nil || h.table.findByIP(ip2) != nil {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}

	MACEntry2, _ = h.table.upsert(StateNormal, mac2, ip2)
	if len(h.table.macTable) != 3 || MACEntry2 != h.table.findByMAC(mac2) || MACEntry2 != h.table.findByIP(ip2) {
		t.Error("expected cannot find MACEntry ", mac2.String(), ip2)
	}
}
