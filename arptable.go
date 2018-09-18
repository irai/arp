package arp

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net"
	"time"
)

type ARPEntry struct {
	MAC        net.HardwareAddr
	IP         net.IP
	PreviousIP net.IP
	State      arpState
	LastUpdate time.Time
	Online     bool
}

type arpState string

const (
	ARPStateNormal      arpState = "normal"
	ARPStateHunt        arpState = "hunt"    // force client to change IP
	ARPStateVirtualHost arpState = "virtual" // virtual host on the network
	ARPStateDeleted     arpState = "deleted" // virtual host on the network
// ARPStateCapture     = "capture" // keep arp spoofing client
)

func (c *ARPHandler) PrintTable() {
	log.Infof("ARP Table: %v entries", len(c.table))
	for _, v := range c.table {
		log.WithFields(log.Fields{"clientmac": v.MAC.String(), "clientip": v.IP.String()}).
			Infof("ARP table %5v %10s %18s  %14s previous %14s", v.Online, v.State, v.MAC, v.IP, v.PreviousIP)
	}
}

func (c *ARPHandler) FindMAC(mac string) *ARPEntry {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for i := range c.table {
		if c.table[i].MAC.String() == mac {
			return &c.table[i]
		}
	}
	return nil
}

func (c *ARPHandler) FindIP(ip net.IP) *ARPEntry {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if ip.Equal(net.IPv4zero) {
		return nil
	}

	for i := range c.table {
		if c.table[i].IP.Equal(ip) {
			return &c.table[i]
		}
	}
	return nil
}

func (c *ARPHandler) GetTable() (table []ARPEntry) {
	for i := range c.table {
		if c.table[i].State != ARPStateVirtualHost && c.table[i].State != ARPStateDeleted {
			table = append(table, c.table[i])
		}
	}
	return table
}

func (c *ARPHandler) arpTableAppend(state arpState, clientMAC net.HardwareAddr, clientIP net.IP) (ret *ARPEntry) {
	mac := DupMAC(clientMAC)    // copy the underlying slice
	ip := DupIP(clientIP).To4() // copy the underlysing slice

	log.WithFields(log.Fields{"ip": ip.String(), "mac": mac.String()}).Warn("ARP new mac detected")

	c.mutex.Lock()

	// Attempt to reuse deleted entry if available
	for i := range c.table {
		if c.table[i].State == ARPStateDeleted {
			c.table[i].State = state
			c.table[i].MAC = mac
			c.table[i].IP = ip
			c.table[i].LastUpdate = time.Now()
			c.table[i].Online = true
			ret = &c.table[i]
			break
		}
	}

	// Extend table when deleted entries are not available
	if ret == nil {
		entry := ARPEntry{State: state, MAC: mac, IP: ip.To4(), LastUpdate: time.Now(), Online: true}
		c.table = append(c.table, entry)
		ret = &c.table[len(c.table)-1]
	}

	c.mutex.Unlock()

	// Notify if channel given and not virtual host
	// if ret.State != ARPStateVirtualHost && c.notification != nil {
	// c.notification <- *ret
	// }

	c.PrintTable()
	return ret
}

func (c *ARPHandler) delete(entry *ARPEntry) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	log.WithFields(log.Fields{"clientmac": entry.MAC, "clientip": entry.IP}).
		Infof("ARP delete entry online %5v state %10s", entry.Online, entry.State)

	entry.State = ARPStateDeleted
	entry.MAC = net.HardwareAddr{}
	entry.IP = net.IPv4zero
	entry.PreviousIP = net.IPv4zero
}

func (c *ARPHandler) deleteVirtualMAC(ip net.IP) {
	virtual := c.FindIP(ip)

	if virtual == nil || (virtual != nil && virtual.State != ARPStateVirtualHost) {
		//	log.Errorf("ARP error non-existent virtual IP %s", ip)
		return
	}

	virtual.State = ARPStateDeleted
	virtual.MAC = net.HardwareAddr{}
	virtual.IP = net.IPv4zero
	virtual.PreviousIP = net.IPv4zero
}

func ARPNewVirtualMAC() net.HardwareAddr {
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
