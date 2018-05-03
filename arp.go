package arp

import (
	marp "github.com/mdlayher/arp"
	log "github.com/sirupsen/logrus"
	"net"
	"spinifex/base"
	"sync"
	"time"
)

type ARPEntry struct {
	MAC        net.HardwareAddr
	IP         net.IP
	PreviousIP net.IP
	// callback   func(srcHwAddr net.HardwareAddr, srcIP net.IP)
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

const (
	checkDeviceOnlineInterval = time.Second * 120
	offlineMinutes            = checkDeviceOnlineInterval*2 + time.Minute
)

type ARPConfig struct {
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
	notification chan<- ARPEntry // Notification channel for new entries
	tranChannel  chan<- ARPEntry // timeTransition channel for arp hunt ent
	config       ARPConfig
	workers      base.GoroutinePool
}

var (
	writeTimeout, _ = time.ParseDuration("100ms")
	ScanTimeout, _  = time.ParseDuration("5s")

	EthernetBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

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

// request send ARP request from src to dst
// multiple goroutines can call request simultaneously.
//
// Request is almost always broadcast but unicast can be used to maintain ARP table;
// i.e. unicast polling check for stale ARP entries; useful to test online/offline state
//
// ARP: packet types
//      note that RFC 3927 specifies 00:00:00:00:00:00 for Request TargetMAC
// +============+===+===========+===========+============+============+===================+===========+
// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
// +============+===+===========+===========+============+============+===================+===========+
// | request    | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  targetIP |
// | reply      | 2 | clientMAC | targetMAC | targetMAC  | targetIP   | clientMAC         |  clientIP |
// | gratuitous | 2 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// +============+===+===========+===========+============+============+===================+===========+
//
func (c *ARPClient) request(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	arp, err := marp.NewPacket(marp.OperationRequest, srcHwAddr, srcIP, dstHwAddr, dstIP)
	if err != nil {
		return err
	}

	if err := c.client.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		log.Error(err)
	}

	return c.client.WriteTo(arp, EthernetBroadcast)
}

func (c *ARPClient) Request(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	if srcIP.Equal(dstIP) {
		log.WithFields(log.Fields{"srcmac": srcHwAddr, "srcip": srcIP, "dstmac": dstHwAddr, "dstip": dstIP}).Debugf("ARP send announcement - I am %s", dstIP)
	} else {
		log.WithFields(log.Fields{"srcmac": srcHwAddr, "srcip": srcIP, "dstmac": dstHwAddr, "dstip": dstIP}).Debugf("ARP send request - who is %s", dstIP)
	}
	return c.request(srcHwAddr, srcIP, dstHwAddr, dstIP)
}

// Reply send ARP reply from the src to the dst
//
// Call with dstHwAddr = ethernet.Broadcast to reply to all
func (c *ARPClient) Reply(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	log.WithFields(log.Fields{"dstmac": dstHwAddr.String(), "dstip": dstIP.String()}).Warnf("ARP send reply - host %s is at %s", srcIP.String(), srcHwAddr.String())
	return c.reply(srcHwAddr, srcIP, dstHwAddr, dstIP)
}

func (c *ARPClient) reply(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	p, err := marp.NewPacket(marp.OperationReply, srcHwAddr, srcIP, dstHwAddr, dstIP)
	if err != nil {
		return err
	}

	if err := c.client.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		log.Fatal(err)
	}

	return c.client.WriteTo(p, dstHwAddr)
}

// The term 'ARP Probe' is used to refer to an ARP Request packet, broadcast on the local link,
// with an all-zero 'sender IP address'. The 'sender hardware address' MUST contain the hardware address of the
// interface sending the packet. The 'sender IP address' field MUST be set to all zeroes,
// to avoid polluting ARP caches in other hosts on the same link in the case where the address turns out
// to be already in use by another host. The 'target IP address' field MUST be set to the address being probed.
// An ARP Probe conveys both a question ("Is anyone using this address?") and an
// implied statement ("This is the address I hope to use.").
func (c *ARPClient) Probe(ip net.IP) error {
	return c.Request(c.config.HostMAC, net.IPv4zero, EthernetBroadcast, ip)
}

// probeUnicast is used to validate the client is still online; same as ARP probe but unicast to target
func (c *ARPClient) probeUnicast(mac net.HardwareAddr, ip net.IP) error {
	return c.Request(c.config.HostMAC, net.IPv4zero, mac, ip)
}

// Having probed to determine that a desired address may be used safely,
// a host implementing this specification MUST then announce that it
// is commencing to use this address by broadcasting ANNOUNCE_NUM ARP
// Announcements, spaced ANNOUNCE_INTERVAL seconds apart.  An ARP
// Announcement is identical to the ARP Probe described above, except
// that now the sender and target IP addresses are both set to the
// host's newly selected IPv4 address.  The purpose of these ARP
// Announcements is to make sure that other hosts on the link do not
// have stale ARP cache entries left over from some other host that may
// previously have been using the same address.  The host may begin
// legitimately using the IP address immediately after sending the first
// of the two ARP Announcements;
func (c *ARPClient) announce(mac net.HardwareAddr, ip net.IP) error {
	return c.announceUnicast(mac, ip, EthernetBroadcast)
}

func (c *ARPClient) announceUnicast(mac net.HardwareAddr, ip net.IP, targetMac net.HardwareAddr) (err error) {
	err = c.Request(mac, ip, targetMac, ip)
	go func() {
		time.Sleep(time.Second * 1)
		c.Request(mac, ip, targetMac, ip)
		time.Sleep(time.Second * 1)
	}()
	return err
}

// arpScanLoop detect new MACs and also when existing MACs are no longer online.
// Send ARP request to all 255 IP addresses first time then send ARP request every so many minutes.
// Probe known macs more often in case they left the network.
//
// checkNewDevicesInterval is the the duration between full scans
//
// Note: ARP loop should not run when there is a hunt in progress
func (c *ARPClient) arpScanLoop(checkNewDevicesInterval time.Duration) (err error) {
	// Goroutine pool
	h := c.workers.Begin("scanloop", false)
	defer h.End()

	c.discover()

	// Ticker used to perform full scan
	checkNewDevices := time.NewTicker(checkNewDevicesInterval).C
	checkDeviceOnline := time.NewTicker(checkDeviceOnlineInterval).C
	for {
		// timer for probing known macs
		select {
		case <-checkNewDevices:
			c.discover()

		case <-c.workers.StopChannel:
			log.Info("ARP stopping probeLoop")
			return nil

		case <-checkDeviceOnline:
			c.checkOnline()
		}
	}
	return nil
}

func (c *ARPClient) checkOnline() {

	c.mutex.Lock()
	table := c.table[:]
	c.mutex.Unlock()

	now := time.Now()
	refreshThreshold := now.Add(checkDeviceOnlineInterval * -1) // Refresh entries last updated before this time
	offlineThreshold := now.Add(offlineMinutes * -1)            // Mark offline entries last updated before this time
	stopThreshold := now.Add(time.Minute * 60 * -1)             // Stop probing entries that have not responded in last hour

	log.Info("ARP refresh online devices")
	for i := range table {

		// Ignore virtual entries - these are always online
		if table[i].State == ARPStateVirtualHost {
			continue
		}

		// Delete from ARP table if the device was not seen for the last hour
		if table[i].LastUpdate.Before(stopThreshold) {
			if table[i].Online == true {
				log.Error("ARP device is not offline during delete")
			}
			c.delete(&table[i])
			continue
		}

		var err error
		// probe only in these two cases:
		//   1) device is online and have not received an update recently; or
		//   2) device is offline and no more than one hour has passed.
		//
		// Probe virtualHosts too so we get the real target to respond; do not set it to offline.
		//
		if (table[i].Online == true && table[i].LastUpdate.Before(refreshThreshold)) ||
			(table[i].Online == false && table[i].LastUpdate.After(stopThreshold)) {

			// Do not send request for devices in hunt state; the IP is zero
			switch table[i].State {
			case ARPStateHunt:
				err = c.probeUnicast(table[i].MAC, table[i].PreviousIP)
			default:
				err = c.probeUnicast(table[i].MAC, table[i].IP)
			}

			if err != nil {
				log.Error("Error ARP request: ", table[i].IP, table[i].MAC, err)
			}

			// Give it a chance to update
			time.Sleep(time.Millisecond * 15)

			if table[i].LastUpdate.Before(offlineThreshold) {
				if table[i].Online == true {
					log.WithFields(log.Fields{"clientmac": table[i].MAC, "clientip": table[i].IP}).Warn("ARP device is offline")

					table[i].Online = false
					table[i].LastUpdate = now

					// Notify upstream the device changed to offline
					if c.notification != nil {
						c.notification <- table[i]
					}
				}
			}
		}
	}
}

func (c *ARPClient) discover() error {

	// Copy underneath array so we can modify value.
	ip := net.ParseIP(c.config.HomeLAN.IP.String()).To4()

	log.Info("ARP Discovering IP - sending 254 ARP requests")
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// Skip entries that are online; these will be checked somewhere else
		//
		if entry := c.ARPFindIP(ip); entry != nil && entry.Online {
			log.WithFields(log.Fields{"clientmac": entry.MAC, "clientip": entry.IP}).Debug("ARP skip request for online device")
			continue
		}

		err := c.request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, ip)
		if err != nil {
			log.Error("ARP request error ", err)
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				log.Info("ARP error in read socket is temporary - retry", err1)
				time.Sleep(time.Millisecond * 100) // Wait before retrying
				continue
			}

			return err
		}
		time.Sleep(time.Millisecond * 25)
	}

	return nil
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
		// if c.notification != nil {
		// c.notification <- *client
		// }
	}
	return 0
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
			c.arpScanLoop(scanInterval)
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
