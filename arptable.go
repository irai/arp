package arp

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// IPEntry holds info about each IP
type IPEntry struct {
	IP          net.IP
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
	// ipTable  map[string]*IPEntry
}

func newARPTable() *arpTable {
	t := &arpTable{macTable: make(map[string]*MACEntry, 32)}
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
func (e MACEntry) String() string {
	ips := make([]string, len(e.IPs))
	for i := range e.IPs {
		ips = append(ips, fmt.Sprintf("%s (%v)", e.IPs[i].IP, time.Since(e.IPs[i].LastUpdated)))
	}
	return fmt.Sprintf("%5v %6s mac=%17s since=%v ips=%v", e.Online, e.State, e.MAC, time.Since(e.LastUpdated), ips)
}

func (t *arpTable) printTable() {

	// Don't lock; it is called from multiple locked locations
	table := t.macTable
	for _, v := range table {
		log.Printf("ARP table %s", v)
	}
}

func (t *arpTable) findByMAC(mac net.HardwareAddr) *MACEntry {
	entry, _ := t.macTable[string(mac)]
	return entry
}

// findByIP return the MACEntry or nil if not found.
func (t *arpTable) findVirtualIP(ip net.IP) *MACEntry {
	for _, v := range t.macTable {
		if v.State != StateVirtualHost {
			continue
		}
		if _, ok := v.IPs[string(ip)]; ok {
			return v
		}
	}
	return nil
}

// findVirtualIP return the MACEntry or nil if not found.
func (t *arpTable) findByIP(ip net.IP) *MACEntry {
	for _, v := range t.macTable {
		if v.State == StateVirtualHost {
			continue
		}
		if _, ok := v.IPs[string(ip)]; ok {
			return v
		}
	}
	return nil
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

func (e *MACEntry) updateIP(ip net.IP) (entry IPEntry, found bool) {
	_, ok := e.IPs[string(ip)]

	now := time.Now()
	entry = IPEntry{IP: ip, LastUpdated: now}
	e.IPs[string(ip)] = entry
	e.LastUpdated = now
	return entry, ok
}

func (e *MACEntry) freeIPs() {
	e.IPs = make(map[string]IPEntry, 6)
}

func (t *arpTable) upsert(state arpState, mac net.HardwareAddr, ip net.IP) (entry *MACEntry, found bool) {

	now := time.Now()
	e, found := t.macTable[string(mac)]
	if !found {
		e = &MACEntry{State: state, MAC: mac, IPs: make(map[string]IPEntry, 6), LastUpdated: now, Online: false}
		t.macTable[string(mac)] = e
		if Debug {
			log.WithFields(log.Fields{"ip": ip, "mac": mac}).Debug("ARP new mac detected")
		}
	} else {
		e.State = state
		e.LastUpdated = now
		e.Online = false
	}

	if ip == nil {
		return e, found
	}

	// replace IP value
	ipEntry, ok := e.IPs[string(ip)]
	ipEntry = IPEntry{IP: ip, LastUpdated: now}
	e.IPs[string(ip)] = ipEntry
	if found && ok {
		return e, true
	}

	return e, false
}

func (t *arpTable) delete(mac net.HardwareAddr) {
	e, _ := t.macTable[string(mac)]
	if Debug {
		log.WithFields(log.Fields{"mac": mac}).Debugf("ARP delete MACEntry %s", e)
	}
	if e == nil {
		return
	}
	delete(t.macTable, string(mac))
}

func newVirtualHardwareAddr() net.HardwareAddr {
	buf := make([]byte, 6)
	rand.Read(buf) // always return nil error; see signature

	// Set the local bit
	buf[0] = (buf[0] | 2) & 0xfe // Set local bit, ensure unicast address
	mac, _ := net.ParseMAC(fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]))
	return mac
}
