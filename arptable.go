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

// How many IPs to keep
const nIPs = 4

// MACEntry holds a mac to ip MACEntry
type MACEntry struct {
	MAC         net.HardwareAddr
	ipArray     [nIPs]IPEntry
	State       arpState
	LastUpdated time.Time
	Online      bool
}

// IP returns the last IP detected
func (e *MACEntry) IP() net.IP {
	return e.ipArray[0].IP
}

// IPs return list of IPs associated with this entry
func (e *MACEntry) IPs() []net.IP {
	ips := make([]net.IP, 0, nIPs)
	for i := range e.ipArray {
		if e.ipArray[i].IP != nil {
			ips = append(ips, e.ipArray[i].IP)
		}
	}
	return ips
}

func (e *MACEntry) findIP(ip net.IP) net.IP {
	for i := range e.ipArray {
		if ip.Equal(e.ipArray[i].IP) {
			return ip
		}
	}
	return nil
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
	// ips := make([]string, len(e.ipArray))
	// for i := range e.ipArray {
	// ips = append(ips, fmt.Sprintf("%s (%v)", e.ipArray[i].IP, time.Since(e.ipArray[i].LastUpdated)))
	// }
	return fmt.Sprintf("%5v %6s mac=%17s since=%v ips=%v", e.Online, e.State, e.MAC, time.Since(e.LastUpdated), e.IPs())
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
		if v.findIP(ip) != nil {
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
		if v.findIP(ip) != nil {
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

	now := time.Now()
	// common path - IP is the same
	if ip.Equal(e.ipArray[0].IP) {
		e.ipArray[0].LastUpdated = now
		return e.ipArray[0], true
	}

	// If in hunt state, ignore any previous IP
	if e.State == StateHunt && e.findIP(ip) != nil {
		return IPEntry{}, true
		// e.freeIPs() // delete previous IPs
	}

	// push all down by one
	i := nIPs - 1
	for i > 0 {
		e.ipArray[i] = e.ipArray[i-1]
		i = i - 1
	}
	entry = IPEntry{IP: ip.To4(), LastUpdated: now}
	e.ipArray[0] = entry
	e.LastUpdated = now
	return entry, false
}

func (e *MACEntry) freeIPs() {
	for i := range e.ipArray {
		e.ipArray[i] = IPEntry{}
	}
}

func (t *arpTable) upsert(state arpState, mac net.HardwareAddr, ip net.IP) (entry *MACEntry, found bool) {

	now := time.Now()
	e, found := t.macTable[string(mac)]
	if !found {
		e = &MACEntry{State: state, MAC: mac, LastUpdated: now, Online: false}
		t.macTable[string(mac)] = e
		if Debug {
			log.Debugf("ARP new mac=%s ip=%s state=%s created", mac, ip, state)
		}
	} else {
		e.State = state
		e.LastUpdated = now
		e.Online = false
	}

	if ip == nil {
		return e, found
	}

	_, ok := e.updateIP(ip)
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
