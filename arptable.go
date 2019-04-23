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
	PreviousIP net.IP
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
				Infof("ARP table %5v %10s %18s  %14s previous %14s", v.Online, v.State, v.MAC, v.IP, v.PreviousIP)
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
		if c.table[i] != nil && c.table[i].IP.Equal(ip) {
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
	mac := DupMAC(clientMAC)    // copy the underlying slice
	ip := DupIP(clientIP).To4() // copy the underlysing slice

	log.WithFields(log.Fields{"ip": ip.String(), "mac": mac.String()}).Warn("ARP new mac detected")

	c.mutex.Lock()

	// Attempt to reuse deleted entry if available
	for i := range c.table {
		if c.table[i] == nil {
			c.table[i] = &Entry{}
			c.table[i].State = state
			c.table[i].MAC = mac
			c.table[i].IP = ip
			c.table[i].LastUpdate = time.Now()
			c.table[i].Online = true
			ret = c.table[i]
			break
		}
	}

	// Extend table when deleted entries are not available
	if ret == nil {
		entry := &Entry{State: state, MAC: mac, IP: ip.To4(), LastUpdate: time.Now(), Online: true}
		c.table = append(c.table, entry)
		ret = c.table[len(c.table)-1]
	}

	c.mutex.Unlock()

	// c.PrintTable()
	return ret
}

func (c *Handler) deleteVirtualMAC(ip net.IP) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for i := range c.table {
		if c.table[i] != nil && c.table[i].IP.Equal(ip) && c.table[i].State == StateVirtualHost {

			c.table[i] = nil

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
