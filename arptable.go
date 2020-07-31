package arp

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// IPMACEntry holds info about each IP
type IPEntry struct {
	IP          net.IP
	MACEntry    *MACEntry
	LastUpdated time.Time
}

// MACEntry holds a mac to ip MACEntry
type MACEntry struct {
	MAC         net.HardwareAddr
	IPs         map[string]IPEntry
	State       arpState
	LastUpdated time.Time
	Online      bool
}

func (e *MACEntry) findIP(ip net.IP) net.IP {
	entry, _ := e.IPs[string(ip)]
	return entry.IP
}

type arpTable struct {
	macTable map[string]*MACEntry
	ipTable  map[string]*IPEntry
}

func newARPTable() *arpTable {
	t := &arpTable{macTable: make(map[string]*MACEntry, 32), ipTable: make(map[string]*IPEntry)}
	return t
}

type arpState string

const (
	// StateNormal is used when there is nothing to do
	StateNormal arpState = "normal"

	// StateHunt when activelly hunting the client to change its IP address
	StateHunt arpState = "hunt"

	// StateVirtualHost when claiming an IP address
	StateVirtualHost arpState = "virtual"
)

// String interface
func (e *MACEntry) String() {
	fmt.Sprintf("%5v %10s %18s  %14s  %v", e.Online, e.State, e.MAC, e.IPs, time.Since(e.LastUpdated))
}

func (t *arpTable) findByMAC(mac net.HardwareAddr) *MACEntry {
	entry, _ := t.macTable[string(mac)]
	return entry
}

// findByIP return the MACEntry or nil if not found.
func (t *arpTable) findVirtualIP(ip net.IP) *MACEntry {
	e, _ := t.ipTable[string(ip)]
	if e == nil || e.MACEntry.State == StateVirtualHost {
		return nil
	}
	return e.MACEntry
}

// findVirtualIP return the MACEntry or nil if not found.
func (t *arpTable) findByIP(ip net.IP) *MACEntry {
	e, _ := t.ipTable[string(ip)]
	if e == nil {
		return nil
	}
	return e.MACEntry
}

// GetTable return a shallow copy of the arp table
func (t *arpTable) getTable() (table []MACEntry) {
	table = make([]MACEntry, 0, len(t.macTable)) // create an array large enough
	for _, MACEntry := range t.macTable {
		if MACEntry != nil && MACEntry.State != StateVirtualHost {
			table = append(table, *MACEntry)
		}
	}
	return table
}

func (t *arpTable) updateIP(e *MACEntry, ip net.IP) (entry *IPEntry, found bool) {
	now := time.Now()
	e.IPs[string(ip)] = IPEntry{IP: ip, LastUpdated: now}

	found = true
	ipEntry, _ := t.ipTable[string(ip)]
	if ipEntry == nil {
		ipEntry = &IPEntry{IP: ip, LastUpdated: time.Now(), MACEntry: e}
		t.ipTable[string(ip)] = ipEntry
		found = false
	} else {
		ipEntry.MACEntry = e
		ipEntry.LastUpdated = e.LastUpdated
	}
	return ipEntry, found
}

func (t *arpTable) upsert(state arpState, mac net.HardwareAddr, ip net.IP) (*MACEntry, bool) {
	newEntry := false

	// insert or update mac
	e, _ := t.macTable[string(mac)]
	if e == nil {
		e = &MACEntry{State: state, MAC: mac, IPs: make(map[string]net.IP, 6), LastUpdated: time.Now(), Online: false}
		t.macTable[string(mac)] = e
		newEntry = true
		if LogAll {
			log.WithFields(log.Fields{"ip": ip, "mac": mac}).Debug("ARP new mac detected")
		}
	} else {
		e.State = state
		e.LastUpdated = time.Now()
		e.Online = false
	}

	if ip == nil {
		return e, newEntry
	}

	// insert or update ip
	ipEntry, _ := t.ipTable[string(ip)]
	if ipEntry == nil {
		e.IPs[string(ip)] = ip
		ipEntry = &IPEntry{IP: ip, LastUpdated: time.Now(), MACEntry: e}
		t.ipTable[string(ip)] = ipEntry
	} else {
		e.IPs[string(ip)] = ip
		ipEntry.MACEntry = e
		ipEntry.LastUpdated = time.Now()
	}

	return e, newEntry
}

func (t *arpTable) delete(mac net.HardwareAddr) {
	e, _ := t.macTable[string(mac)]
	if LogAll {
		log.WithFields(log.Fields{"mac": mac}).Debugf("ARP delete MACEntry %s", e)
	}
	if e == nil {
		return
	}
	ips := e.IPs
	delete(t.macTable, string(mac))
	for _, v := range ips {
		delete(t.ipTable, string(v))
	}
}

func (t *arpTable) deleteIP(ip net.IP) {
	e, _ := t.ipTable[string(ip)]
	if e == nil {
		return
	}

	if LogAll {
		log.WithFields(log.Fields{"ip": ip}).Debugf("ARP delete ip entry %+v", e)
	}

	// delete IP from mac table and delete mac entry if last IP
	delete(e.MACEntry.IPs, string(ip))
	if len(e.MACEntry.IPs) <= 0 {
		t.delete(e.MACEntry.MAC)
	}

	delete(t.ipTable, string(ip))
}

func (t *arpTable) deleteVirtualMAC(virtual *MACEntry) error {

	entry, _ := t.macTable[string(virtual.MAC)]
	if entry == nil {
		return fmt.Errorf("virtual mac does not exist: %v", virtual.MAC)
	}

	if !bytes.Equal(entry.MAC, virtual.MAC) || entry.State != StateVirtualHost {
		return fmt.Errorf("failed to delete non virtual mac: %v %v %v", virtual.MAC, entry.MAC, entry.State)
	}

	delete(t.macTable, string(virtual.MAC))
	return nil
}

func newVirtualHardwareAddr() net.HardwareAddr {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		log.Error("ARP error in new virtual MAC", err)
		return net.HardwareAddr{}
	}
	// Set the local bit
	buf[0] = (buf[0] | 2) & 0xfe // Set local bit, ensure unicast address
	mac, _ := net.ParseMAC(fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]))
	return mac
}
