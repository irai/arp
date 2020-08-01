package arp

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// ForceIPChange performs the following:
//  1. set client state to "hunt" which will continuously spoof the client ARP table
//  2. create a virtual host to claim the reallocated IP
//  3. spoof the client IP to redirect all traffic to host
//  4. callback when we receive a change of IP for the client
//
// client will revert back to "normal" when a new IP is detected for the MAC
func (c *Handler) ForceIPChange(mac net.HardwareAddr) error {
	if Debug {
		log.WithFields(log.Fields{"mac": mac}).Debug("ARP capture force IP change")
	}

	c.Lock()
	defer c.Unlock()

	client := c.table.findByMAC(mac)
	if client == nil {
		err := fmt.Errorf("mac %s is not online", mac)
		return err
	}

	if client.State == StateHunt {
		err := fmt.Errorf("mac %s already in hunt state", mac)
		return err
	}

	client.State = StateHunt
	go c.spoofLoop(c.ctx, client)

	return nil
}

// StopIPChange terminate the hunting process
func (c *Handler) StopIPChange(mac net.HardwareAddr) error {
	if Debug {
		log.WithFields(log.Fields{"mac": mac}).Debug("ARP stop IP change")
	}

	c.Lock()
	defer c.Unlock()

	client := c.table.findByMAC(mac)
	if client == nil {
		err := fmt.Errorf("mac %s not found", mac)
		return err
	}

	if client.State != StateHunt {
		err := fmt.Errorf("mac %s not in hunt state", mac)
		if Debug {
			log.WithFields(log.Fields{"mac": mac}).Debugf("ARP client not in hunt state: %s", client.State)
		}
		return err
	}

	// This will end the spoof goroutine
	client.State = StateNormal
	return nil
}

// FakeIPConflict tricks clients to send a new DHCP request to capture the name.
// It is used to get the initial client name.
//
func (c *Handler) FakeIPConflict(clientHwAddr net.HardwareAddr, clientIP net.IP) {
	if Debug {
		log.WithFields(log.Fields{"mac": clientHwAddr.String(), "ip": clientIP.String()}).Debug("ARP fake IP conflict")
	}

	go func() {

		for i := 0; i < 7; i++ {
			c.request(c.config.HostMAC, clientIP, EthernetBroadcast, clientIP) // Send ARP announcement
			time.Sleep(time.Millisecond * 10)
			// Reply(virtual.MAC, virtual.IP, arpClient.table[i].MAC, virtual.IP) // Send gratuitous ARP reply
			// Send ARP reply to broadcast MAC

			c.Reply(c.config.HostMAC, clientIP, clientHwAddr, clientIP) // Send gratuitous ARP reply
		}
	}()
}

// IPChanged is used to notify that the IP has changed.
//
// The package will detect IP changes automatically however some clients do not
// send ARP Collision Detection packets and hence do not appear as an immediate change.
// This method is used to accelerate the change for example when a
// new DHCP MACEntry has been allocated.
//
func (c *Handler) IPChanged(clientHwAddr net.HardwareAddr, clientIP net.IP) {
	// Do nothing if we already have this mac and ip
	if client := c.table.findByMAC(clientHwAddr); client != nil && client.findIP(clientIP) != nil && client.Online {
		return
	}

	if Debug {
		log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Debug("ARP new mac or ip - validating")
	}
	if err := c.Request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
		log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Error("ARP request failed", err)
	}

	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(time.Second * 1)
			if MACEntry := c.table.findByMAC(clientHwAddr); MACEntry != nil && MACEntry.findIP(clientIP) != nil {
				if Debug {
					log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Debug("ARP found mac")
				}
				return
			}

			// Silent request
			if err := c.request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
				log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Error("ARP request 2 failed", err)
			}
		}
		log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Info("ARP could not detect IP")
		c.table.printTable()
	}()
}

// spoofLoop creates a virtual host spoof the target IPs
// until it changes IP or go offline.
//
// It will send a number of ARP packets to:
//   1. spoof the client arp table to send router packets to us
//   2. claim the ownership of the IP
//
func (c *Handler) spoofLoop(ctx context.Context, client *MACEntry) {

	// 4 second re-arp seem to be adequate;
	// Experimented with 300ms but no noticeable improvement other the chatty net.
	ticker := time.NewTicker(time.Second * 4).C

	// create a virtual host and add IPs to its table
	// Virtual Host will exist while this goroutine is running
	virtual, _ := c.table.upsert(StateVirtualHost, newVirtualHardwareAddr(), nil)
	virtual.Online = true
	startTime := time.Now()
	nTimes := 0
	mac := client.MAC
	for {
		c.Lock()

		log.WithFields(log.Fields{"mac": mac}).Infof("ARP claim IP start %v", startTime)

		// Always search for MAC in case it has been deleted.
		client := c.table.findByMAC(mac)
		if client == nil || client.State != StateHunt {
			c.table.delete(virtual.MAC)
			log.WithFields(log.Fields{"mac": mac, "ips": client.IPs}).Infof("ARP claim IP end repeat=%v duration=%v", nTimes, time.Now().Sub(startTime))
			return
		}

		if nTimes%16 == 0 {
			log.WithFields(log.Fields{"mac": mac.String()}).Infof("ARP claim IP repeat=%v duration=%v", nTimes, time.Now().Sub(startTime))
		}
		nTimes++

		// update ips - list may have been updated
		for _, v := range client.IPs {
			virtual.updateIP(v.IP)
		}

		c.Unlock()

		for _, v := range virtual.IPs {

			// Re-arp target to change router to host so all traffic comes to us
			// i.e. tell target I am 192.168.0.1
			//
			// Use virtual IP as it is guaranteed to not change.
			c.forceSpoof(mac, v.IP)

			// Use VirtualHost to request ownership of the IP; try to force target to acquire another IP
			c.forceAnnouncement(virtual.MAC, v.IP)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker:
		}
	}
}

// forceSpoof send gratuitous ARP packet to spoof client MAC table to send router packets to host instead of the router
// i.e.  192.168.0.1->RouterMAC becames 192.168.0.1->HostMAC
//
// The client ARP table is refreshed often and only last for a short while (few minutes)
// hence the goroutine that re-arp clients
// To make sure the cache stays poisoned, replay every 10 seconds with a loop.
//
//
func (c *Handler) forceSpoof(mac net.HardwareAddr, ip net.IP) error {

	// Announce to target that we own the router IP
	// Unicast announcement - this will not work for all devices but should cause no pain
	err := c.announceUnicast(c.config.HostMAC, c.config.RouterIP, mac)
	if err != nil {
		log.WithFields(log.Fields{"mac": mac.String(), "ip": ip}).Error("ARP error send announcement packet", err)
		return err
	}

	// Send 3 unsolicited ARP reply; clients may discard this
	for i := 0; i < 2; i++ {
		err = c.reply(c.config.HostMAC, c.config.RouterIP, mac, ip)
		if err != nil {
			log.WithFields(log.Fields{"mac": mac.String(), "ip": ip}).Error("ARP spoof client error", err)
			return err
		}
		time.Sleep(time.Millisecond * 10)
	}

	return nil
}

// forceAnnounce send a ARP packets to tell the network we are using the IP.
func (c *Handler) forceAnnouncement(mac net.HardwareAddr, ip net.IP) error {
	err := c.announce(mac, ip)
	if err != nil {
		log.WithFields(log.Fields{"mac": mac.String(), "ip": ip}).Error("ARP error send announcement packet", err)
	}

	// Send 4 gratuitous ARP reply : Log the first one only
	err = c.Reply(mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply
	for i := 0; i < 3; i++ {
		if err != nil {
			log.WithFields(log.Fields{"mac": mac.String(), "ip": ip}).Error("ARP error send gratuitous packet", err)
		}
		time.Sleep(time.Millisecond * 10)

		// Dont show in log
		err = c.reply(mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply
	}

	return nil
}
