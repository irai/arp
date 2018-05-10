package arp

import (
	marp "github.com/mdlayher/arp"
	log "github.com/sirupsen/logrus"
	"net"
	"spinifex/base"
	"sync"
	"time"
)

type configuration struct {
	NIC       string           `yaml:"-"`
	HostMAC   net.HardwareAddr `yaml:"-"`
	HostIP    net.IP           `yaml:"-"`
	RouterIP  net.IP           `yaml:"-"`
	RouterMAC net.HardwareAddr `yaml:"-"`
	HomeLAN   net.IPNet        `yaml:"-"`
}

type ARPClient struct {
	client       *marp.Client
	mutex        sync.Mutex
	table        []ARPEntry
	notification chan<- ARPEntry // notification channel for state change
	tranChannel  chan<- ARPEntry // notification channel for arp hunt ent
	config       configuration
	workers      base.GoroutinePool
}

var (
	CIDR_169_254 = net.IPNet{IP: net.IPv4(169, 254, 0, 0), Mask: net.IPv4Mask(255, 255, 0, 0)}
)

func getArpClient(nic string) (*marp.Client, error) {
	ifi, err := net.InterfaceByName(nic)
	if err != nil {
		log.Error("ARP Reply error in interface name", err)
		return nil, err
	}

	// Set up ARP client with socket
	c, err := marp.Dial(ifi)
	if err != nil {
		log.Error("ARP Reply error in dial", err)
		return nil, err
	}
	return c, nil
}

func NewARPClient(nic string, hostMAC net.HardwareAddr, hostIP net.IP, routerIP net.IP, homeLAN net.IPNet) (c *ARPClient, err error) {
	c = &ARPClient{}
	c.client, err = getArpClient(nic)
	if err != nil {
		log.WithFields(log.Fields{"nic": nic}).Error("ARP error in dial", err)
		return nil, err
	}

	c.table = make([]ARPEntry, 0, 64)
	c.config.NIC = nic
	c.config.HostMAC = hostMAC
	c.config.HostIP = hostIP
	c.config.RouterIP = routerIP
	c.config.HomeLAN = homeLAN

	c.workers.Init("ARP")

	log.WithFields(log.Fields{"hostinterface": c.config.NIC, "hostmac": c.config.HostMAC.String(),
		"hostip": c.config.HostIP.String(), "lanrouter": c.config.RouterIP.String()}).Info("ARP configuration")

	return c, nil
}

// AddNotificationChannel set notification channel for new ARP entries. It will
// automatically send notification for each entry in ARP table.
//
func (c *ARPClient) AddNotificationChannel(notification chan<- ARPEntry) {
	c.notification = notification
	for i := range c.table {
		c.notification <- c.table[i]
	}
}

// AddTransitionChannel set transition channel for ARP entries. Used to notify of
// ARPHunt end.
//
func (c *ARPClient) AddTransitionChannel(channel chan<- ARPEntry) {
	c.tranChannel = channel
}

func (c *ARPClient) Stop() error {

	// Close the arp socket
	c.client.Close()

	// closing stopChannel will cause all waiting goroutines to exit
	return c.workers.Stop()
}

func (c *ARPClient) actionUpdateClient(client *ARPEntry, senderMAC net.HardwareAddr, senderIP net.IP) int {
	// client.LastUpdate = time.Now()

	// Update IP if client changed
	// Ignore router updates: our router broadcast 169.254.x.x local link IP.
	//
	if !client.IP.Equal(senderIP) && !senderIP.Equal(net.IPv4zero) &&
		senderMAC.String() != c.config.RouterMAC.String() &&
		!senderIP.Equal(c.config.HostIP) &&
		!CIDR_169_254.Contains(senderIP) {
		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": client.IP.String()}).Infof("ARP client changed IP to %s", senderIP.String())
		c.mutex.Lock()
		virtual := client.PreviousIP
		client.PreviousIP = client.IP
		client.IP = net.ParseIP(senderIP.String()).To4()
		client.State = ARPStateNormal
		c.mutex.Unlock()
		c.deleteVirtualMAC(virtual)

		return 1
	}
	return 0
}

// IPChanged notify arp logic that the IP has changed.
// This is likely as a result of a DHCP change. Some clients do
// not send ARP Collision Detection packets and hence do not appear as an ARP change.
func (c *ARPClient) IPChanged(clientHwAddr net.HardwareAddr, clientIP net.IP) {
	client := c.ARPFindMAC(clientHwAddr.String())

	// Do nothing if we already have this mac and ip
	if client != nil && client.IP.Equal(clientIP) {
		return
	}

	log.WithFields(log.Fields{"clientmac": clientHwAddr, "clientip": clientIP}).Info("ARP new mac or ip - validating")
	if err := c.Request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
		log.WithFields(log.Fields{"clientmac": clientHwAddr, "clientip": clientIP}).Error("ARP request failed", err)
	}

	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(time.Second * 2)
			if entry := c.ARPFindMAC(clientHwAddr.String()); entry != nil && entry.IP.Equal(clientIP) {
				log.WithFields(log.Fields{"clientmac": clientHwAddr, "clientip": clientIP}).Info("ARP found mac")
				return
			}

			// Silent request
			if err := c.request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, clientIP); err != nil {
				log.WithFields(log.Fields{"clientmac": clientHwAddr, "clientip": clientIP}).Error("ARP request 2 failed", err)
			}
		}
		log.WithFields(log.Fields{"clientmac": clientHwAddr, "clientip": clientIP}).Error("ARP mac/ip pair does not exist")
		c.ARPPrintTable()
	}()
}

// ARPListenAndServe wait for ARP packets and action these.
//
// State table:
//   from = sender mac
//   to   = target IP
//
// Request   from_MAC  to_IP     action1               action 2
//           normal    router    actionUpdateTable
//           normal    host      actionUpdateTable (linux to respond)
//           normal    new       actionUpdateTable
//           normal    normal    actionUpdateTable
//           normal    virtual   actionReply
//           capture   router    actionClaimIP
//           capture   host      actionClaimIP
//           capture   new       actionDHCP (the client is changing IP?)
//           capture   virtual   actionClaimIP (gratuitous announcement?)
//           capture   normal    actionClaimIP
//           router    virtual   actionReply
// Reply     from_MAC  to_IP     action1               action 2
//           normal    host      actionUpdateTable
//           capture   host      actionClaimIP (the client still claim the IP)
func (c *ARPClient) ARPListenAndServe(scanInterval time.Duration) {
	// Goroutine pool
	h := c.workers.Begin("listenandserve", true)
	defer h.End()

	// Goroutine to continualsy scan for network devices
	go func() {
		if scanInterval != time.Duration(0) {
			time.Sleep(time.Millisecond * 10)
			c.pollingLoop(scanInterval)
		}
	}()

	// Set ZERO timeout to block forever
	if err := c.client.SetReadDeadline(time.Time{}); err != nil {
		log.Error("ARP error in socket:", err)
		return
	}

	// Loop and wait for replies
	for {

		packet, _, err := c.client.Read()
		if err != nil {
			log.Error("ARP read error ", err)
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				log.Info("ARP read error is temporary - retry", err1)
				time.Sleep(time.Millisecond * 30) // Wait a few seconds before retrying
				continue
			}
			return
		}

		notify := 0

		sender := c.ARPFindMAC(packet.SenderHardwareAddr.String())
		if sender == nil {
			// If new client, the create a new entry in table
			// NOTE: if this is a probe, the sender IP will be Zeros
			sender = c.arpTableAppend(ARPStateNormal, packet.SenderHardwareAddr, packet.SenderIP)
			notify += 1
		}

		if sender.Online == false {
			sender.Online = true
			notify += 1
			log.WithFields(log.Fields{"clientmac": sender.MAC, "clientip": sender.IP}).Warn("ARP device is online")
		}
		sender.LastUpdate = time.Now()

		// log.Debugf("ARP loop received packet type %v - mac %s", packet.Operation, sender.MAC.String())

		// Skip packets that we sent as virtual host
		if sender.State == ARPStateVirtualHost {
			continue
		}

		switch packet.Operation {

		// Reply to ARP request if we are spoofing this host.
		//
		case marp.OperationRequest:
			log.WithFields(log.Fields{"clientip": sender.IP.String(), "clientmac": sender.MAC.String(),
				"to_ip": packet.TargetIP.String(), "to_mac": packet.TargetHardwareAddr}).Debugf("ARP request received - who is %s tell %s", packet.TargetIP.String(), sender.IP.String())

			// if target is virtual host, reply and return
			target := c.ARPFindIP(packet.TargetIP)
			if target != nil && target.State == ARPStateVirtualHost {
				log.WithFields(log.Fields{"ip": target.IP, "mac": target.MAC}).Info("ARP sending reply for virtual mac")
				c.Reply(target.MAC, target.IP, EthernetBroadcast, target.IP)
				break
			}

			switch sender.State {
			case ARPStateHunt:
				c.actionRequestInHuntState(sender, packet.SenderIP, packet.TargetIP)

			case ARPStateNormal:
				notify += c.actionUpdateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)

			// case ARPStateVirtualHost:
			// arpReplyVirtualMAC(packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)

			default:
				log.Error("ARP unexpected client state in request =", sender.State)
			}

		case marp.OperationReply:
			log.WithFields(log.Fields{
				"clientip": sender.IP, "clientmac": sender.MAC,
				"senderip": packet.SenderIP.String(), "to_mac": packet.TargetHardwareAddr, "to_ip": packet.TargetIP}).
				Infof("ARP reply received - %s is at %s", packet.SenderIP, sender.MAC)

			switch sender.State {
			case ARPStateNormal:
				notify += c.actionUpdateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)

			case ARPStateHunt:
				// Android does not send collision detection request,
				// we will see a reply instead. Check if the address has changed.
				if !packet.SenderIP.Equal(net.IPv4zero) && !packet.SenderIP.Equal(sender.PreviousIP) {
					notify += c.actionUpdateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)
				} else {

					// c.actionClaimIP(sender)
				}

			case ARPStateVirtualHost: // Captured our own reply - Do nothing
			// arpReplyVirtualMAC(packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)

			default:
				log.WithFields(log.Fields{"clientip": sender.IP, "clientmac": sender.MAC}).Error("ARP unexpected client state in reply =", sender.State)
			}

		}

		if notify > 0 && c.notification != nil {
			c.notification <- *sender
		}
	}
}
