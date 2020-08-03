package arp

import (
	"net"
	"testing"
)

var (
	zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	hostMAC   = net.HardwareAddr{0xff, 0xff, 0x03, 0x04, 0x05, 0x01}
	hostIP    = net.ParseIP("192.168.0.129").To4()
	homeLAN   = net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}
	routerMAC = net.HardwareAddr{0xff, 0xff, 0x03, 0x04, 0x05, 0x02}
	routerIP  = net.ParseIP("192.168.0.1").To4()
	ip2       = net.ParseIP("192.168.0.2").To4()
	ip3       = net.ParseIP("192.168.0.3").To4()
	ip4       = net.ParseIP("192.168.0.4").To4()
	ip5       = net.ParseIP("192.168.0.5").To4()
	mac1      = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x01}
	mac2      = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x02}
	mac3      = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x03}
	mac4      = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x04}
	mac5      = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x05}
	localIP   = net.IPv4(169, 254, 0, 10)
)

func Test_AddSimple(t *testing.T) {

	h := testHandler(t)
	MACEntry, _ := h.table.upsert(StateNormal, mac1, ip4)

	if MACEntry != h.table.findByMAC(mac1) || MACEntry != h.table.findByIP(ip4) {
		t.Error("expected cannot find MACEntry ", mac1.String(), ip4)
	}
}

func Test_AddMany(t *testing.T) {

	h := testHandler(t)

	MACEntry, _ := h.table.upsert(StateNormal, mac1, ip4)
	MACEntry2, _ := h.table.upsert(StateNormal, mac2, ip2)
	MACEntry3, _ := h.table.upsert(StateNormal, mac3, ip3)

	h.table.printTable()
	if len(h.table.macTable) != 3 || MACEntry != h.table.findByMAC(mac1) || MACEntry != h.table.findByIP(ip4) {
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
		t.Error("expected cannot find MACEntry 2 third", len(h.table.macTable), mac1.String(), ip4)
	}
}
func Test_Delete(t *testing.T) {

	h := testHandler(t)
	h.table.upsert(StateNormal, mac1, ip4)
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

func Test_DuplicateIP(t *testing.T) {
	h := testHandler(t)
	e, _ := h.table.upsert(StateNormal, mac1, ip2)
	e.Online = true
	e.updateIP(ip3)
	if !e.IP().Equal(ip3) && len(e.IPs()) != 2 {
		t.Fatal("expected ip3 ", e.IP())
	}
	e.updateIP(ip2)
	if !e.IP().Equal(ip2) && len(e.IPs()) != 3 {
		t.Fatal("expected ip2-2 ", e.IP())
	}
	e.updateIP(ip4)
	if !e.IP().Equal(ip4) && len(e.IPs()) != 4 {
		t.Fatal("expected ip2 ", e.IP())
	}
	e.updateIP(ip5)
	if !e.IP().Equal(ip5) && len(e.IPs()) != 4 {
		t.Fatal("expected ip5 ", e.IP())
	}
	e.updateIP(ip2)
	if !e.IP().Equal(ip2) && len(e.IPs()) != 4 {
		t.Fatal("expected ip2-2 ", e.IP())
	}

	if !e.ipArray[0].IP.Equal(ip2) || !e.ipArray[1].IP.Equal(ip5) || !e.ipArray[2].IP.Equal(ip4) || !e.ipArray[3].IP.Equal(ip2) {
		t.Fatal("invalid IPs", e.IPs())
	}
}
func Test_HuntIP(t *testing.T) {
	h := testHandler(t)

	e, _ := h.table.upsert(StateNormal, mac1, ip2)
	e.updateIP(ip3)
	e.Online = true
	e.State = StateHunt

	e.updateIP(ip3)
	if !e.IP().Equal(ip3) && len(e.IPs()) != 2 {
		t.Fatal("expected ip3 ", e.IP())
	}
	e.updateIP(ip2)
	if !e.IP().Equal(ip3) && len(e.IPs()) != 2 {
		t.Fatal("expected ip2 ", e.IP())
	}
	e.updateIP(ip4)
	if !e.IP().Equal(ip4) && len(e.IPs()) != 3 {
		t.Fatal("expected ip4 ", e.IP())
	}
	e.updateIP(ip2)
	if !e.IP().Equal(ip4) && len(e.IPs()) != 3 {
		t.Fatal("expected ip2-2 ", e.IP())
	}
	e.updateIP(ip5)
	if !e.IP().Equal(ip5) && len(e.IPs()) != 4 {
		t.Fatal("expected ip5 ", e.IP())
	}
	e.updateIP(ip3)
	if !e.IP().Equal(ip3) && len(e.IPs()) != 4 {
		t.Fatal("expected ip3-2 ", e.IP())
	}

	if !e.ipArray[0].IP.Equal(ip5) || !e.ipArray[1].IP.Equal(ip4) || !e.ipArray[2].IP.Equal(ip3) || !e.ipArray[3].IP.Equal(ip2) {
		t.Fatal("invalid IPs", e.IPs())
	}

}
