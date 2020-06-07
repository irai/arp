package arp

import (
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
func (c *Handler) ForceIPChange(clientHwAddr net.HardwareAddr, clientIP net.IP) error {
	if LogAll {
		log.WithFields(log.Fields{"mac": clientHwAddr.String(), "ip": clientIP.String()}).Debug("ARP capture force IP change")
	}

	client := c.FindMAC(clientHwAddr)
	if client == nil {
		err := fmt.Errorf("mac %s is not online", clientHwAddr.String())
		if LogAll {
			log.Debug("ARP nothing to do - ", err)
		}
		return err
	}

	if client.State == StateHunt {
		err := fmt.Errorf("client already in hunt state %s ", client.IP.String())
		if LogAll {
			log.Debug("ARP error in ForceIPChange", err)
		}
		return err
	}

	if client.IP.Equal(clientIP) == false {
		err := fmt.Errorf("ARP capture error missmatch in client table with actual client %s vs %s", client.IP.String(), clientIP.String())
		log.Warn("ARP unexpected IP missmatch - do nothing", err)
		return err
	}

	// Set client to Hunt
	client.State = StateHunt

	// client.IP = nextFakeIP()

	// spoof client until end of hunt phase
	go c.spoofLoop(client)

	return nil
}

// StopIPChange terminate the hunting process
func (c *Handler) StopIPChange(clientHwAddr net.HardwareAddr) (err error) {
	if LogAll {
		log.WithFields(log.Fields{"mac": clientHwAddr.String()}).Debug("ARP stop IP change")
	}

	client := c.FindMAC(clientHwAddr)
	if client == nil {
		log.WithFields(log.Fields{"mac": clientHwAddr}).Error("ARP mac not found")
		err = fmt.Errorf("mac %s is not online", clientHwAddr.String())
		return err
	}

	if client.State != StateHunt {
		if LogAll {
			log.WithFields(log.Fields{"mac": client.MAC.String(), "ip": client.IP}).Debug("ARP client is not in hunt state", client.State)
		}
	}

	// this will terminate the spoof gorotutine and delete the Virtual MAC
	client.State = StateNormal
	return nil
}

// FakeIPConflict tricks clients to send a new DHCP request to capture the name.
// It is used to get the initial client name.
//
func (c *Handler) FakeIPConflict(clientHwAddr net.HardwareAddr, clientIP net.IP) {
	if LogAll {
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
// new DHCP entry has been allocated.
//
func (c *Handler) IPChanged(clientHwAddr net.HardwareAddr, clientIP net.IP) {
	// Do nothing if we already have this mac and ip
	if client := c.FindMAC(clientHwAddr); client != nil && client.IP.Equal(clientIP) && client.Online {
		return
	}

	if LogAll {
		log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Debug("ARP new mac or ip - validating")
	}
	if err := c.Request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
		log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Error("ARP request failed", err)
	}

	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(time.Second * 1)
			if entry := c.FindMAC(clientHwAddr); entry != nil && entry.IP.Equal(clientIP) {
				if LogAll {
					log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Debug("ARP found mac")
				}
				return
			}

			// Silent request
			if err := c.request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
				log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Error("ARP request 2 failed", err)
			}
		}
		log.WithFields(log.Fields{"mac": clientHwAddr, "ip": clientIP}).Error("ARP mac/ip pair does not exist")
		c.PrintTable()
	}()
}

// spoofLoop create a virtual host to handle this IP and will spoof
//           the target until it changes IP or go offline.
//
// It will send a number of ARP packets to:
//   1. spoof the client arp table to send router packets to us
//   2. claim the ownership of the IP
//
func (c *Handler) spoofLoop(client *Entry) {

	// Goroutine pool
	h := c.goroutinePool.Begin("ARP hunt " + client.MAC.String())
	defer h.End()

	// Virtual Host will exist while this goroutine is running
	c.mutex.Lock()
	virtual := c.arpTableAppendLocked(StateVirtualHost, newVirtualHardwareAddr(), client.IP)
	virtual.Online = true
	c.mutex.Unlock()

	// Always search for MAC in case it has been deleted.
	mac := client.MAC
	nTimes := 0
	startTime := time.Now()

	log.WithFields(log.Fields{"mac": mac.String(), "ip": virtual.IP}).Infof("ARP claim IP start %v", startTime)

	for {
		client = c.FindMAC(mac)
		if h.Stopping() == true || client == nil || client.State != StateHunt {
			c.deleteVirtualMAC(virtual)
			newIP := net.IPv4zero
			if client != nil {
				newIP = client.IP
			}
			log.WithFields(log.Fields{"mac": mac.String(), "ip": virtual.IP, "newIP": newIP}).Infof("ARP claim IP end repeat=%v duration=%v", nTimes, time.Now().Sub(startTime))
			return
		}

		if nTimes%16 == 0 {
			log.WithFields(log.Fields{"mac": mac.String(), "ip": virtual.IP}).Infof("ARP claim IP repeat=%v duration=%v", nTimes, time.Now().Sub(startTime))
		}
		nTimes++

		// Re-arp target to change router to host so all traffic comes to us
		// i.e. tell target I am 192.168.0.1
		//
		// Use virtual IP as it is guaranteed to not change.
		c.forceSpoof(client.MAC, virtual.IP) // NOTE: virtual is the target IP

		// Use VirtualHost to request ownership of the IP; try to force target to acquire another IP
		c.forceAnnouncement(virtual.MAC, virtual.IP)

		// 4 second re-arp seem to be adequate;
		// Experimented with 300ms but no noticeable improvement other the chatty net.
		time.Sleep(time.Second * 4)
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
