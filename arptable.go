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
	for _, v := range c.table {
		if v != nil {
			log.WithFields(log.Fields{"clientmac": v.MAC.String(), "clientip": v.IP.String()}).
				Infof("ARP table %5v %10s %18s  %14s", v.Online, v.State, v.MAC, v.IP)
		}
	}
}

// FindMAC return the entry or nil if not found.
func (c *Handler) FindMAC(mac net.HardwareAddr) *Entry {
	c.mutex.Lock()
	defer c.mutex.Unlock()

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
			c.table[i].IP.Equal(ip) && c.table[i].State != StateHunt {
			return c.table[i]
		}
	}
	return nil
}

// GetTable return a shallow copy of the arp table
func (c *Handler) GetTable() (table []*Entry) {
	for i := range c.table {
		if c.table[i] != nil && c.table[i].State != StateVirtualHost {
			table = append(table, c.table[i])
		}
	}
	return table
}

func (c *Handler) arpTableAppend(state arpState, clientMAC net.HardwareAddr, clientIP net.IP) (ret *Entry) {
	mac := dupMAC(clientMAC) // copy the underlying slice
	ip := dupIP(clientIP)    // copy the underlysing slice

	log.WithFields(log.Fields{"ip": ip.String(), "mac": mac.String()}).Warn("ARP new mac detected")

	entry := &Entry{State: state, MAC: mac, IP: ip.To4(), LastUpdate: time.Now(), Online: true}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Attempt to reuse deleted entry if available
	table := c.table // to be safe,  don't want c.table to change on us 
	for i := range table {
		if table[i] == nil {
			table[i] = entry
			return entry
		}
	}

	// Don't extend table when past the maximum capacity. The initial table
	// should have plenty of capacity to store all IPs (ie. 256 capacity)
	// This will cause a buffer rellocation and likely result in pointer errors in 
	// other goroutines.
	if len(c.table) >= cap(c.table) {
		log.Error("arptable is too big", len(c.table), cap(c.table))
		return nil
	}
	_ = append(c.table, entry)

	// c.PrintTable()
	return entry
}

func (c *Handler) deleteVirtualMAC(ip net.IP) {
	c.mutex.Lock()
	defer log.Error("RETURNING from deleteVirtualMAC", ip)
	defer c.mutex.Unlock()

	for i := range c.table {
		if c.table[i] != nil && c.table[i].IP.Equal(ip) && c.table[i].State == StateVirtualHost {

			// c.table[i] = nil
			// soft delete; will be deleted when no longer in use
			c.table[i].LastUpdate = time.Now()
			c.PrintTable()

			return
		}
	}
	log.Errorf("ARP deleting error non-existent virtual IP %s", ip)
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
