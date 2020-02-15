package arp

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// Entry holds a mac to ip entry
type Entry struct {
	MAC        net.HardwareAddr
	IP         net.IP
	State      arpState
	LastUpdate time.Time
	Online     bool
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

// PrintTable will print the ARP table to stdout.
func (c *Handler) PrintTable() {
	log.Infof("ARP Table: %v entries", len(c.table))

	// Don't mutex lock; it is called from multiple locked locations
	table := c.table
	for _, v := range table {
		if v != nil {
			log.WithFields(log.Fields{"mac": v.MAC.String(), "ip": v.IP.String()}).
				Infof("ARP table %5v %10s %18s  %14s  %v", v.Online, v.State, v.MAC, v.IP, time.Since(v.LastUpdate))
		}
	}
}

// FindMAC return the entry or nil if not found.
func (c *Handler) FindMAC(mac net.HardwareAddr) *Entry {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.findMACLocked(mac)
}

// findMACLocked
//
// CAUTION: Lock the mutex before calling this.
func (c *Handler) findMACLocked(mac net.HardwareAddr) *Entry {
	for i := range c.table {
		if c.table[i] != nil && bytes.Equal(c.table[i].MAC, mac) {
			return c.table[i]
		}
	}
	return nil
}

// FindIP return the entry or nil if not found.
func (c *Handler) FindIP(ip net.IP) *Entry {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if ip.Equal(net.IPv4zero) {
		return nil
	}

	for i := range c.table {
		// When in Hunt state, the IP is claimed by a virtual host; ignore the entry
		if c.table[i] != nil &&
			c.table[i].IP.Equal(ip) && c.table[i].State != StateVirtualHost {
			return c.table[i]
		}
	}
	return nil
}

// FindVirtualIP return the entry or nil if not found.
func (c *Handler) FindVirtualIP(ip net.IP) *Entry {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, entry := range c.table {
		if entry != nil && entry.State == StateVirtualHost && entry.IP.Equal(ip) {
			return entry
		}
	}
	return nil
}

// GetTable return a shallow copy of the arp table
func (c *Handler) GetTable() (table []*Entry) {
	table = make([]*Entry, 0, len(c.table)) // create an array large enough
	t := c.table
	for _, entry := range t {
		if entry != nil && entry.State != StateVirtualHost {
			table = append(table, entry)
		}
	}
	return table
}

// arpTableAppendLocked
//
// CAUTION: must be called with the mutex already locked. It has a race condition if not locked.
//          call c.mutex.Lock() before entering this function
//
func (c *Handler) arpTableAppendLocked(state arpState, clientMAC net.HardwareAddr, clientIP net.IP) (ret *Entry) {
	mac := dupMAC(clientMAC) // copy the underlying slice
	ip := dupIP(clientIP)    // copy the underlysing slice

	if LogAll {
		log.WithFields(log.Fields{"ip": ip.String(), "mac": mac.String()}).Debug("ARP new mac detected")
	}

	entry := &Entry{State: state, MAC: mac, IP: ip.To4(), LastUpdate: time.Now(), Online: false}

	// Attempt to reuse deleted entry if available
	for i := range c.table {
		if c.table[i] == nil {
			c.table[i] = entry
			return entry
		}
	}

	// Don't extend table when past the maximum capacity. The initial table
	// should have plenty of capacity to store all IPs (ie. 256 capacity)
	// This will cause a buffer rellocation and likely result in pointer errors in
	// other goroutines.
	if len(c.table) >= cap(c.table) {
		log.Error("ARP arptable is too big", len(c.table), cap(c.table))
		return nil
	}

	table := c.table // to be safe test array location -  don't want c.table array to change on us
	c.table = append(c.table, entry)
	if len(table) > 0 && &c.table[0] != &table[0] {
		// tell the world if the underlaying array changed.
		// the logic assume existing pointers will not change
		log.Error("ARP ERROR new table array allocated", len(c.table), cap(c.table))
	}

	return entry
}

func (c *Handler) deleteVirtualMAC(virtual *Entry) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for i := range c.table {
		if c.table[i] != nil && bytes.Equal(c.table[i].MAC, virtual.MAC) && c.table[i].State == StateVirtualHost {
			if LogAll {
				log.WithFields(log.Fields{"ip": c.table[i].IP, "mac": c.table[i].MAC.String()}).Debug("ARP deleting virtual mac")
			}
			c.table[i] = nil
			c.PrintTable()
			return
		}
	}
	log.WithFields(log.Fields{"ip": virtual.IP, "mac": virtual.MAC.String()}).Error("ARP deleting non-existent virtual mac", *virtual)
	c.PrintTable()
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
