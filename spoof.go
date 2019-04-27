package arp

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	tmpIP = net.IPv4(10, 10, 10, 0)
)

func nextFakeIP() net.IP {
	tmpIP[3]++
	if tmpIP[3] > 254 {
		tmpIP[2]++
		tmpIP[3] = 1
	}
	return dupIP(tmpIP)
}

// ForceIPChange performs the following:
//  1. set client state to "hunt" which will continuously spoof the client ARP table
//  2. create a virtual host to claim the reallocated IP
//  3. spoof the client IP to redirect all traffic to host
//  4. callback when we receive a change of IP for the client
//
// client will revert back to "normal" when a new IP is detected for the MAC
func (c *Handler) ForceIPChange(clientHwAddr net.HardwareAddr, clientIP net.IP) error {
	log.WithFields(log.Fields{"clientmac": clientHwAddr.String(), "clientip": clientIP.String()}).Warn("ARP capture force IP change")

	client := c.FindMAC(clientHwAddr)
	if client == nil {
		err := fmt.Errorf("mac %s is not online", clientHwAddr.String())
		log.Warn("ARP nothing to do - ", err)
		return err
	}

	if client.State == StateHunt {
		err := fmt.Errorf("client already in hunt state %s ", client.IP.String())
		log.Error("ARP error in ForceIPChange", err)
		return err
	}

	if client.IP.Equal(clientIP) == false {
		err := fmt.Errorf("ARP capture error missmatch in client table with actual client %s vs %s", client.IP.String(), clientIP.String())
		log.Error("ARP unexpected IP missmatch", err)
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
	log.WithFields(log.Fields{"clientmac": clientHwAddr.String()}).Info("ARP stop IP change")

	client := c.FindMAC(clientHwAddr)
	if client == nil {
		log.WithFields(log.Fields{"clientmac": clientHwAddr}).Error("ARP mac not found")
		err = fmt.Errorf("mac %s is not online", clientHwAddr.String())
		return err
	}

	if client.State != StateHunt {
		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": client.IP}).Error("ARP client is not in hunt state")
		err = fmt.Errorf("mac %s is not in hunt state", clientHwAddr.String())
		return err
	}

	// this will terminate the spoof gorotutine and delete the Virtual MAC
	client.State = StateNormal
	return nil
}

// FakeIPConflict tricks clients to send a new DHCP request to capture the name.
// It is used to get the initial client name.
//
func (c *Handler) FakeIPConflict(clientHwAddr net.HardwareAddr, clientIP net.IP) {
	log.WithFields(log.Fields{"clientmac": clientHwAddr.String(), "clientip": clientIP.String()}).Warn("ARP fake IP conflict")

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

// actionRequestInHuntState respond to a request from a device that is in Hunt state.
//
func (c *Handler) actionRequestInHuntState(client *Entry, senderIP net.IP, targetIP net.IP) (n int, err error) {

	ip := client.IP // Keep a copy : client.IP may change

	if client == nil || client.State != StateHunt {
		err = fmt.Errorf("client is not in hunt state %s", client.MAC.String())
		log.Error("ARP error: ", err)
		return 0, err
	}

	// We are only interested in ARP Address Conflict Detection packets:
	//
	// +============+===+===========+===========+============+============+===================+===========+
	// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
	// +============+===+===========+===========+============+============+===================+===========+
	// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
	// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
	// +============+===+===========+===========+============+============+===================+===========+
	if !senderIP.Equal(net.IPv4zero) && !senderIP.Equal(targetIP) {
		return 0, nil
	}

	log.WithFields(log.Fields{"clientmac": client.MAC, "clientip": ip}).Infof("ARP request in hunt state for %s", targetIP)

	// Record new IP in ARP table if address has changed.
	// Stop hunting it. The spoof function will detect the mac changed to normal
	// and delete the virtual IP.
	//
	if !targetIP.Equal(ip) { // is this a new IP?
		n := c.actionUpdateClient(client, client.MAC, targetIP)
		if n != 1 {
			log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": ip}).Warnf("ARP failed to change IP to %s", targetIP)
			return 0, fmt.Errorf("error updating client: %s, %s ", client.MAC.String(), ip)
		}

		return n, nil
	}

	log.Warnf("ARP client attempting to get same IP previous %s new %s", ip, targetIP)

	return 0, err
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
	h := c.workers.Begin("ARP hunt " + client.MAC.String())
	defer h.End()

	// Virtual Host will exist while this goroutine is running
	virtual := c.arpTableAppend(StateVirtualHost, newVirtualHardwareAddr(), client.IP)

	// Always search for MAC in case it has been deleted.
	mac := client.MAC
	for {
		client = c.FindMAC(mac)
		if h.Stopping() == true || client == nil || client.State != StateHunt {
			c.deleteVirtualMAC(virtual)
			return
		}

		log.WithFields(log.Fields{"clientmac": mac.String(), "clientip": virtual.IP}).Warn("ARP claiming IP")

		// Re-arp target to change router to host so all traffic comes to us
		// i.e. tell target I am 192.168.0.1
		//
		// Use virtual IP as it is guaranteed to not change.
		c.forceSpoof(client.MAC, virtual.IP) // NOTE: virtual is the target IP

		// Use VirtualHost to request ownership of the IP; try to force target to acquire another IP
		c.forceAnnouncement(virtual.MAC, virtual.IP)

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
		log.WithFields(log.Fields{"clientmac": mac.String(), "clientip": ip}).Error("ARP error send announcement packet", err)
		return err
	}

	// Send 3 unsolicited ARP reply; clients may discard this
	for i := 0; i < 2; i++ {
		err = c.reply(c.config.HostMAC, c.config.RouterIP, mac, ip)
		if err != nil {
			log.WithFields(log.Fields{"clientmac": mac.String(), "clientip": ip}).Error("ARP spoof client error", err)
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
		log.WithFields(log.Fields{"clientmac": mac.String(), "clientip": ip}).Error("ARP error send announcement packet", err)
	}

	// Send 4 gratuitous ARP reply : Log the first one only
	err = c.Reply(mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply
	for i := 0; i < 3; i++ {
		if err != nil {
			log.WithFields(log.Fields{"clientmac": mac.String(), "clientip": ip}).Error("ARP error send gratuitous packet", err)
		}
		time.Sleep(time.Millisecond * 10)

		// Dont show in log
		err = c.reply(mac, ip, EthernetBroadcast, ip) // Send gratuitous ARP reply
	}

	return nil
}
