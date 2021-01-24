package arp

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"log"
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
	IPArray     [nIPs]IPEntry
	State       arpState
	LastUpdated time.Time
	Online      bool
	ClaimIP     bool // if true, will claim the target IP; likely to force the target IP to stop working
}

// IP returns the last IP detected
func (e *MACEntry) IP() net.IP {
	return e.IPArray[0].IP
}

// IPs return list of IPs associated with this entry
func (e *MACEntry) IPs() []net.IP {
	ips := make([]net.IP, 0, nIPs)
	for i := range e.IPArray {
		if e.IPArray[i].IP != nil {
			ips = append(ips, e.IPArray[i].IP)
		}
	}
	return ips
}

func (e *MACEntry) findIP(ip net.IP) net.IP {
	for i := range e.IPArray {
		if ip.Equal(e.IPArray[i].IP) {
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
	if e.Online {
		return fmt.Sprintf("online  %7s mac=%17s since=%v ips=%v", e.State, e.MAC, time.Since(e.LastUpdated), e.IPs())
	}
	return fmt.Sprintf("offline %7s mac=%17s since=%v ips=%v", e.State, e.MAC, time.Since(e.LastUpdated), e.IPs())
}

func (t *arpTable) printTable() {

	// Don't lock; it is called from multiple locked locations
	table := t.macTable
	for _, v := range table {
		log.Printf("ARP entry %s", v)
	}
}

func (t *arpTable) findByMAC(mac net.HardwareAddr) *MACEntry {
	entry, _ := t.macTable[string(mac)]
	return entry
}

// findVirtualIP returns the virtual MACEntry or nil if not found.
func (t *arpTable) findVirtualIP(ip net.IP) *MACEntry {
	for _, v := range t.macTable {
		if v.State != StateVirtualHost {
			continue
		}
		if v.IP().Equal(ip) {
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

// deleteStaleIP removes any duplicate IP in other entries
// This is to prevent an old stale IP in another entry clashing with a newly acquired IP
func (t *arpTable) deleteStaleIP(ee *MACEntry, ip net.IP) {
	if ee.State == StateVirtualHost { // skip if entry is virtual
		return
	}
	for _, e := range t.macTable {
		if e.State == StateVirtualHost {
			continue
		}
		s := e.IPArray[1:] // remove IP duplicates from second element onwards
		for i := range s {
			if s[i].IP.Equal(ip) {
				if i < len(s)-1 {
					copy(s[i:], s[i+1:])
				}
				s[len(s)-1] = IPEntry{}
			}
		}
	}
}

func (t *arpTable) updateIP(e *MACEntry, ip net.IP) (found bool) {

	now := time.Now()
	// common path - IP is the same
	if ip.Equal(e.IPArray[0].IP) {
		e.IPArray[0].LastUpdated = now
		e.LastUpdated = now
		return true
	}

	// If in hunt state, ignore any previous IP
	if e.State == StateHunt && e.findIP(ip) != nil {
		return true
	}

	// remove the IP from other entries if it exist
	t.deleteStaleIP(e, ip)

	// push all entries down by one
	i := nIPs - 1
	for i > 0 {
		e.IPArray[i] = e.IPArray[i-1]
		i = i - 1
	}
	e.IPArray[0].IP = ip.To4()
	e.IPArray[0].LastUpdated = now
	e.LastUpdated = now
	if Debug {
		log.Printf("ARP ip=%s updated mac=%s state=%s ips=%s", ip, e.MAC, e.State, e.IPs())
	}
	return false
}

func (e *MACEntry) freeIPs() {
	for i := range e.IPArray {
		e.IPArray[i] = IPEntry{}
	}
}

func (t *arpTable) upsert(state arpState, mac net.HardwareAddr, ip net.IP) (entry *MACEntry, found bool) {

	now := time.Now()
	e, found := t.macTable[string(mac)]
	if !found {
		e = &MACEntry{State: state, MAC: mac, LastUpdated: now, Online: false}
		t.macTable[string(mac)] = e
		if Debug {
			log.Printf("ARP new mac=%s ip=%s state=%s created", mac, ip, state)
		}
	} else {
		e.State = state
		e.LastUpdated = now
		e.Online = false
	}

	if ip == nil {
		return e, found
	}

	ok := t.updateIP(e, ip)
	if found && ok {
		return e, true
	}

	return e, false
}

func (t *arpTable) delete(mac net.HardwareAddr) {
	e, _ := t.macTable[string(mac)]
	if Debug {
		log.Printf("ARP delete MACEntry entry=%s", e)
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
