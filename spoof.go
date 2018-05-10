package arp

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	// "spinifex/network/icmp"
	"time"
)

// spoof send a gratuitous ARP packet to spoof client MAC table to send router packets to host instead of the router
// i.e.  192.168.0.1->RouterMAC becames 192.168.0.1->HostMAC
//
// The client ARP table is refreshed often and only last for a short while (few minutes)
// hence the goroutine that re-arp clients
// To make sure the cache stays poisoned, replay every 10 seconds with a loop.
//
//
func (c *ARPClient) spoof(client *ARPEntry) error {

	ip := client.IP
	c.mutex.Lock()
	if client.State == ARPStateHunt {
		ip = client.PreviousIP
	}
	c.mutex.Unlock()

	// Announce to target that we own the router IP
	// Unicast announcement - this will not work for all devices but should cause no pain
	err := c.announceUnicast(c.config.HostMAC, c.config.RouterIP, client.MAC)
	if err != nil {
		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": ip.String()}).Error("ARP error send announcement packet", err)
		return err
	}

	for i := 0; i < 2; i++ {
		err = c.reply(c.config.HostMAC, c.config.RouterIP, client.MAC, ip)
		if err != nil {
			log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": ip.String()}).Error("ARP spoof client error", err)
			return err
		}
		time.Sleep(time.Millisecond * 10)
	}

	// Tell the network we have the ownership of the IP; all nodes will update their ARP table to us
	virtual := c.ARPFindIP(ip)
	if virtual == nil || virtual.State != ARPStateVirtualHost {
		err = errors.New(fmt.Sprintf("cannot find virtual host for %s", ip.String()))
		log.Error("ARP error virtual host", err)
		return err
	}

	// announce that we are using this IP
	err = c.announce(virtual.MAC, virtual.IP)
	if err != nil {
		log.WithFields(log.Fields{"clientmac": virtual.MAC.String(), "clientip": virtual.IP.String()}).Error("ARP error send announcement packet", err)
	}

	return nil
}

const retryPeriod = time.Minute * 1

func (c *ARPClient) spoofLoop(client *ARPEntry) {
	defer log.Warn("ARP spoof loop terminated")

	// tryagain := time.Now().Add(retryPeriod)
	for {
		if client.State != ARPStateHunt {
			return
		}

		// Only spoof if ARP is online and ICMP packets are being received back; if not
		// the device is dormant or not present.
		// if client.Online && icmp.Ping(client.PreviousIP) {
		if client.Online {
			/**
			now := time.Now()
			if now.After(tryagain) {
				for i := 0; i < 20; i++ {
					c.actionClaimIP(client)
					if client.State != ARPStateHunt {
						return
					}
				}
				tryagain = now.Add(retryPeriod)
				continue
			}
			***/

			log.WithFields(log.Fields{"clientmac": client.MAC, "clientip": client.IP}).Info("ARP spoof client")
			c.actionClaimIP(client)
			// c.actionClaimIP(client)
			// c.actionClaimIP(client)
			c.spoof(client)
			// c.spoof(client)
			// c.spoof(client)

		}
		time.Sleep(time.Second * 4)
	}
}

// ARPForceIPChange performs the following:
//  1. set client state to "hunt" resetting the client IP in the process.
//  2. create a virtual host to handle the reallocated IP
//  3. spoof the client IP to redirect all traffic to host
//  4. set a callback when we receive a request from this client
//
// client will revert back to "normal" when a new IP is detected for the MAC
func (c *ARPClient) ARPForceIPChange(clientHwAddr net.HardwareAddr, clientIP net.IP) error {
	log.WithFields(log.Fields{"clientmac": clientHwAddr.String(), "clientip": clientIP.String()}).Warn("ARP capture force IP change")

	client := c.ARPFindMAC(clientHwAddr.String())
	if client == nil {
		err := errors.New(fmt.Sprintf("mac %s is not online", clientHwAddr.String()))
		log.Warn("ARP nothing to do - ", err)
		return err
	}

	if client.State == ARPStateHunt {
		err := errors.New(fmt.Sprintf("client already in hunt state %s ", client.IP.String()))
		log.Error("ARP error in ARPForceIPChange", err)
		return err
	}

	if client.IP.Equal(clientIP) == false || client.IP.Equal(net.IPv4zero) {
		err := errors.New(fmt.Sprintf("ARP capture error missmatch in client table with actual client %s vs %s", client.IP.String(), clientIP.String()))
		log.Error("ARP unexpected IP missmatch", err)
		return err
	}

	// Create a virtual host to handle this IP
	c.arpTableAppend(ARPStateVirtualHost, ARPNewVirtualMAC(), clientIP)

	// Set client state to hunt and reset IP address
	c.mutex.Lock()
	client.PreviousIP = net.ParseIP(client.IP.String()).To4()
	client.IP = net.IPv4zero
	client.State = ARPStateHunt
	c.mutex.Unlock()

	go func() {
		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": client.PreviousIP.String()}).Info("ARP hunt start")
		defer log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": client.PreviousIP.String()}).Info("ARP hunt end")

		/****
		// only attack if client is online
		if icmp.Ping(client.PreviousIP) {
			for i := 0; i < 20; i++ {
				log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": virtual.IP}).Infof("ARP hunt claim IP %s", virtual.IP)
				if client.State != ARPStateHunt {
					return
				}

				c.actionClaimIP(client)

				time.Sleep(time.Second * 4)
			}
		} else {
			log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": client.PreviousIP.String()}).Info("ARP hunt device is offline - entering passive mode")
		}
		****/

		// Notify if channel given
		if c.tranChannel != nil {
			c.tranChannel <- *client
		}
		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": client.PreviousIP.String()}).Warn("ARP hunt failed")

		// continue to spoof client until hunt ends
		c.spoofLoop(client)

		//actionStopHunt(client)
	}()
	// Redirect all client traffic to host
	// spoof(client)

	return nil
}

func (c *ARPClient) StopIPChange(clientHwAddr net.HardwareAddr) {
	log.WithFields(log.Fields{"clientmac": clientHwAddr.String()}).Info("ARP stop IP change")

	client := c.ARPFindMAC(clientHwAddr.String())
	if client == nil {
		log.WithFields(log.Fields{"clientmac": clientHwAddr}).Error("ARP mac not found")
		return
	}

	if client.State == ARPStateHunt {
		c.actionStopHunt(client)
	}
}

// ARPFakeConflict tricks clients to send a new DHCP request to capture the name.
// It is used to get the initial client name.
//
func (c *ARPClient) ARPFakeIPConflict(clientHwAddr net.HardwareAddr, clientIP net.IP) {
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

func (c *ARPClient) actionStopHunt(client *ARPEntry) {
	log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": client.PreviousIP.String()}).Info("ARP hunt stop")

	if client.State != ARPStateHunt {
		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": client.PreviousIP.String()}).Error("ARP client is not in hunt state")
		return
	}

	c.deleteVirtualMAC(client.PreviousIP)
	c.mutex.Lock()
	client.State = ARPStateNormal
	client.IP = client.PreviousIP
	client.PreviousIP = net.IPv4zero
	c.mutex.Unlock()
}

func (c *ARPClient) actionRequestInHuntState(client *ARPEntry, senderIP net.IP, targetIP net.IP) (n int, err error) {

	// We are only interested in ARP Address Conflict Detection packets:
	//
	// +============+===+===========+===========+============+============+===================+===========+
	// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
	// +============+===+===========+===========+============+============+===================+===========+
	// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
	// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
	// +============+===+===========+===========+============+============+===================+===========+
	if !senderIP.Equal(net.IPv4zero) && !senderIP.Equal(targetIP) {
		return
	}

	log.WithFields(log.Fields{"clientmac": client.MAC, "clientip": client.IP}).Infof("ARP request in hunt state for %s", targetIP)

	/**
	var ip net.IP
	if senderIP.Equal(net.IPv4zero) {
		ip = targetIP
	} else {
		ip = senderIP
	}
	***/

	// Record new IP in ARP table if address has changed.
	// Stop hunting then.
	//
	if !targetIP.Equal(client.PreviousIP) { // new IP

		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": client.IP}).Infof("ARP request client changed IP to %s", targetIP)

		c.mutex.Lock()
		client.State = ARPStateNormal
		c.mutex.Unlock()

		n := c.actionUpdateClient(client, client.MAC, targetIP)

		return n, nil
	}

	log.Warnf("ARP client attempting to get same IP previous %s new %s", client.PreviousIP, targetIP)

	err = c.actionClaimIP(client)

	return 0, err
}

func (c *ARPClient) actionClaimIP(client *ARPEntry) (err error) {

	ip := client.IP
	c.mutex.Lock()
	if client.State == ARPStateHunt {
		ip = client.PreviousIP
	}
	c.mutex.Unlock()

	log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": ip.String()}).Warnf("ARP capture claim %s", ip.String())

	// Re-arp client so all traffic comes to host
	// i.e. I am 192.168.0.1
	c.spoof(client)

	// Request ownership of the IP; this will force the client to acquire another IP
	// Gratuitous Request will have IP = zero
	virtual := c.ARPFindIP(ip)
	if virtual == nil || virtual.State != ARPStateVirtualHost {
		err = errors.New(fmt.Sprintf("cannot find virtual host for %s", ip.String()))
		log.Error("ARP error virtual host", err)
		return err
	}

	// announce that we are using this IP
	err = c.announce(virtual.MAC, virtual.IP)
	if err != nil {
		log.WithFields(log.Fields{"clientmac": virtual.MAC.String(), "clientip": virtual.IP.String()}).Error("ARP error send announcement packet", err)
	}

	for i := 0; i < 3; i++ {
		c.Reply(virtual.MAC, virtual.IP, client.MAC, virtual.IP) // Send gratuitous ARP reply
		time.Sleep(time.Millisecond * 5)
		err = c.Reply(virtual.MAC, virtual.IP, EthernetBroadcast, virtual.IP) // Send gratuitous ARP reply

		if err != nil {
			log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": client.IP.String()}).Error("ARP error send gratuitous packet", err)
			return err
		}
		time.Sleep(time.Millisecond * 4)
	}

	return nil
}
