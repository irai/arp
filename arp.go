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
	callback   func(srcHwAddr net.HardwareAddr, srcIP net.IP)
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
	probeInterval  = time.Second * 120
	offlineMinutes = probeInterval * 2
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
		log.Error("ARP ARPReply error in interface name", err)
		return nil, err
	}

	// Set up ARP client with socket
	c, err := marp.Dial(ifi)
	if err != nil {
		log.Error("ARP ARPReply error in dial", err)
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

	c.workers.Init("ARPworker")

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
func (c *ARPClient) request(srcHwAddr net.HardwareAddr, srcIP net.IP, dstIP net.IP) error {
	arp, err := marp.NewPacket(marp.OperationRequest, srcHwAddr, srcIP, EthernetBroadcast, dstIP)
	if err != nil {
		return err
	}

	if err := c.client.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		log.Fatal(err)
	}

	return c.client.WriteTo(arp, EthernetBroadcast)
}

// ARPRequest send an ARP Request packet using a new socket client underneath. it does not
func ARPRequest(nic string, srcHwAddr net.HardwareAddr, srcIP net.IP, dstIP net.IP) error {
	log.WithFields(log.Fields{"clientmac": srcHwAddr.String(), "clientip": srcIP.String()}).Debugf("ARP send request who is %s tell %s", dstIP.String(), srcIP.String())
	c, err := NewARPClient(nic, net.HardwareAddr{}, net.IP{}, net.IP{}, net.IPNet{})
	if err != nil {
		return err
	}

	return c.request(srcHwAddr, srcIP, dstIP)
}

// ARPReply send ARP reply from the src to the dst
//
// Call with dstHwAddr = ethernet.Broadcast to reply to all
func (c *ARPClient) ARPReply(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	// c, err := getArpClient()
	// if err != nil {
	// return err
	// }
	// defer c.Close()

	log.WithFields(log.Fields{"dstmac": dstHwAddr.String(), "dstip": dstIP.String()}).Warnf("ARP send reply - host %s is at %s", srcIP.String(), srcHwAddr.String())
	p, err := marp.NewPacket(marp.OperationReply, srcHwAddr, srcIP, dstHwAddr, dstIP)
	if err != nil {
		return err
	}

	if err := c.client.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		log.Fatal(err)
	}

	return c.client.WriteTo(p, dstHwAddr)
}

func (c *ARPClient) ARPPrintTable() {
	log.Infof("ARP Table: %v entries", len(c.table))
	for _, v := range c.table {
		log.WithFields(log.Fields{"clientmac": v.MAC.String(), "clientip": v.IP.String()}).
			Infof("ARP table %5v %10s %18s  %14s previous %14s", v.Online, v.State, v.MAC, v.IP, v.PreviousIP)
	}
}

// arpScanLoop detect new MACs and also when existing MACs are no longer online.
// Send ARP request to all 255 IP addresses first time then send ARP request every so many minutes.
// Probe known macs more often in case they left the network.
//
// refreshDuration is the the duration between full scans
//
// Note: ARP loop should not run when there is a hunt in progress
func (c *ARPClient) arpScanLoop(refreshDuration time.Duration) error {
	// Goroutine pool
	h := c.workers.Begin()
	defer h.End()

	c.arpProbe()

	// Ticker used to perform full scan
	ticker := time.NewTicker(refreshDuration).C
	for {
		// timer for probing known macs
		probe := time.NewTimer(probeInterval).C
		select {
		case <-ticker:
			c.arpProbe()

		case <-c.workers.StopChannel:
			log.Info("ARP stopping probeLoop")
			return nil

		case <-probe:
			c.mutex.Lock()
			table := c.table[:]
			c.mutex.Unlock()

			now := time.Now()
			refreshThreshold := now.Add(probeInterval * -1)
			offlineThreshold := now.Add(offlineMinutes * -1)

			log.Info("ARP refresh online devices")
			for i := range table {
				// Don't probe if we received an update recently or if the device is offline.
				if table[i].State == ARPStateNormal &&
					table[i].Online == true &&
					table[i].LastUpdate.Before(refreshThreshold) {
					log.Infof("ARP refresh ip %s", table[i].IP)
					err := c.request(c.config.HostMAC, c.config.HostIP, table[i].IP) // Request
					if err != nil {
						log.Error("Error ARP request: ", table[i].IP, err)
					}
					// Give it a chance to update
					time.Sleep(time.Millisecond * 15)

					if table[i].LastUpdate.Before(offlineThreshold) {
						table[i].Online = false
					}
				}
			}
		}
	}
	return nil
}

func (c *ARPClient) arpProbe() error {

	// Copy underneath array so we can modify value.
	ip := net.ParseIP(c.config.HomeLAN.IP.String()).To4()

	log.Info("ARP Discovering IP - sending 254 ARP requests")
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// err := ARPRequest(c.config.HostMAC, net.IPv4zero, ip) // Send ARP Probe
		// log.Debugf("ARP probe ip %s", ip.String())
		err := c.request(c.config.HostMAC, c.config.HostIP, ip) // Request
		if err != nil {
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				log.Info("ARP error in read socket is temporary - retry", err1)
				time.Sleep(time.Millisecond * 100) // Wait before retrying
				continue
			}
			if c.workers.Stopping {
				log.Info("ARP arpProbe goroutine stopping normally")
				return nil
			}

			log.Error("ARP arpProbe goroutine terminating: ", err)
			return err
		}
		time.Sleep(time.Millisecond * 25)
	}

	return nil
}

func (c *ARPClient) ARPProbeIP(ip net.IP) {
	c.request(c.config.HostMAC, c.config.HostIP, ip) // Request
	time.Sleep(time.Millisecond * 50)
	c.request(c.config.HostMAC, c.config.HostIP, ip) // Request
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
	h := c.workers.Begin()
	defer h.End()

	// Goroutine to continualsy scan for network devices
	go func() { time.Sleep(time.Millisecond * 10); c.arpScanLoop(scanInterval) }()

	// Set ZERO timeout to block forever
	if err := c.client.SetReadDeadline(time.Time{}); err != nil {
		log.Error("ARP error in socket:", err)
		return
	}

	// Loop and wait for replies
	for {

		packet, _, err := c.client.Read()
		if err != nil {
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				log.Info("ARP error in read socket is temporary - retry", err1)
				time.Sleep(time.Millisecond * 30) // Wait a few seconds before retrying
				continue
			}
			if c.workers.Stopping {
				log.Info("ARP listenandserver goroutine stopping normally")
			} else {
				log.Fatal("ARP error listenandserve goroutine terminating: ", err)
			}
			return
		}

		sender := c.ARPFindMAC(packet.SenderHardwareAddr.String())
		if sender == nil {
			// If new client, the create a new entry in table
			// NOTE: if this is a probe, the sender IP will be Zeros
			sender = c.arpTableAppend(ARPStateNormal, packet.SenderHardwareAddr, packet.SenderIP)
		}

		sender.Online = true
		sender.LastUpdate = time.Now()

		// log.Debugf("ARP loop received packet type %v - mac %s", packet.Operation, sender.MAC.String())

		switch packet.Operation {

		// Reply to ARP request if we are spoofing this host.
		//
		case marp.OperationRequest:
			log.WithFields(log.Fields{"clientip": sender.IP.String(), "clientmac": sender.MAC.String(),
				"to_ip": packet.TargetIP.String()}).Debugf("ARP request received - who is %s tell %s", packet.TargetIP.String(), sender.IP.String())

			// if target is virtual host, reply and return
			target := c.ARPFindIP(packet.TargetIP)
			if target != nil && target.State == ARPStateVirtualHost {
				log.WithFields(log.Fields{"ip": target.IP, "mac": target.MAC}).Info("ARP sending reply for virtual mac")
				c.ARPReply(target.MAC, target.IP, EthernetBroadcast, target.IP)
				break
			}

			switch sender.State {
			case ARPStateHunt:
				c.actionRequestInHuntState(sender, packet.SenderIP, packet.TargetIP)

			case ARPStateNormal:
				c.actionUpdateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)

			// case ARPStateVirtualHost:
			// arpReplyVirtualMAC(packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)

			default:
				log.Error("ARP unexpected client state in request =", sender.State)
			}

		case marp.OperationReply:
			log.WithFields(log.Fields{"clientip": sender.IP, "clientmac": sender.MAC,
				"senderip": packet.SenderIP.String(), "target_ip": packet.TargetIP.String()}).Infof("ARP reply received - %s is at %s", packet.SenderIP.String(), sender.MAC.String())

			switch sender.State {
			case ARPStateNormal:
				c.actionUpdateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)

			case ARPStateHunt:
				// Android does not send collision detection request,
				// we will see a reply instead. Check if the address has changed.
				if !packet.SenderIP.Equal(net.IPv4zero) && !packet.SenderIP.Equal(sender.PreviousIP) {
					c.actionUpdateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)
				} else {
					c.actionClaimIP(sender, packet.SenderHardwareAddr, packet.SenderIP)
				}

			case ARPStateVirtualHost: // Captured our own reply - Do nothing
			// arpReplyVirtualMAC(packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)

			default:
				log.WithFields(log.Fields{"clientip": sender.IP, "clientmac": sender.MAC}).Error("ARP unexpected client state in reply =", sender.State)
			}

		}
	}
}
