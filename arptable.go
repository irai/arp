package arp

import (
	log "github.com/sirupsen/logrus"
	"net"
	"spinifex/network"
	"time"
)

func (c *ARPClient) ARPPrintTable() {
	log.Infof("ARP Table: %v entries", len(c.table))
	for _, v := range c.table {
		log.WithFields(log.Fields{"clientmac": v.MAC.String(), "clientip": v.IP.String()}).
			Infof("ARP table %5v %10s %18s  %14s previous %14s", v.Online, v.State, v.MAC, v.IP, v.PreviousIP)
	}
}

func (c *ARPClient) ARPFindMAC(mac string) *ARPEntry {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for i := range c.table {
		if c.table[i].MAC.String() == mac {
			return &c.table[i]
		}
	}
	return nil
}

func (c *ARPClient) ARPFindIP(ip net.IP) *ARPEntry {
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

func (c *ARPClient) ARPGetTable() (table []ARPEntry) {
	for i := range c.table {
		if c.table[i].State != ARPStateVirtualHost && c.table[i].State != ARPStateDeleted {
			table = append(table, c.table[i])
		}
	}
	return table
}

func (c *ARPClient) arpTableAppend(state arpState, clientMAC net.HardwareAddr, clientIP net.IP) (ret *ARPEntry) {
	mac := network.DupMAC(clientMAC)    // copy the underlying slice
	ip := network.DupIP(clientIP).To4() // copy the underlysing slice

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

	c.ARPPrintTable()
	return ret
}

func (c *ARPClient) deleteVirtualMAC(ip net.IP) {
	virtual := c.ARPFindIP(ip)

	if virtual == nil || (virtual != nil && virtual.State != ARPStateVirtualHost) {
		//	log.Errorf("ARP error non-existent virtual IP %s", ip)
		return
	}

	virtual.State = ARPStateDeleted
	virtual.IP = net.IPv4zero
}
