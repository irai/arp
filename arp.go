package arp

import (
	"errors"
	"fmt"
	marp "github.com/mdlayher/arp"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net"
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
	tranChannel  chan<- ARPEntry // Transition channel for arp hunt ent
	config       ARPConfig
}

var (
	// config *db.Config

	ReplyTimeout, _ = time.ParseDuration("100ms")
	ScanTimeout, _  = time.ParseDuration("5s")

	arpClient2 ARPClient = ARPClient{}

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

	if err := c.client.SetWriteDeadline(time.Now().Add(ReplyTimeout)); err != nil {
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

	if err := c.client.SetWriteDeadline(time.Now().Add(ReplyTimeout)); err != nil {
		log.Fatal(err)
	}

	return c.client.WriteTo(p, dstHwAddr)
}

func (c *ARPClient) ARPPrintTable() {
	log.Infof("ARP Table: %v entries", len(c.table))
	for _, v := range c.table {
		log.WithFields(log.Fields{"clientmac": v.MAC.String(), "clientip": v.IP.String()}).Infof("ARP table %5v %10s %18s  %14s previous %14s", v.Online, v.State, v.MAC, v.IP, v.PreviousIP)
	}
}

// ARPProbeLoop send a ARP request to all 255 IP addresses first time.
//              then just update existing mac addresses
//
// Note: ARP loop should not run when there is a hunt in progress
func (c *ARPClient) ARPProbeLoop(refreshDuration time.Duration) error {

	c.arpProbe()

	go func() {
		for {
			time.Sleep(refreshDuration)
			c.arpProbe()
		}
	}()

	ticker := time.NewTicker(probeInterval)
	for range ticker.C {
		c.mutex.Lock()
		table := c.table[:]
		c.mutex.Unlock()
		now := time.Now()

		for i := range table {
			if table[i].State == ARPStateNormal {
				log.Debugf("ARP probe ip %s", table[i].IP)
				err := c.request(c.config.HostMAC, c.config.HostIP, table[i].IP) // Request
				if err != nil {
					log.Error("Error ARP request: ", table[i].IP, err)
				}
				time.Sleep(time.Millisecond * 25)

				if now.Sub(table[i].LastUpdate) > offlineMinutes {
					table[i].Online = false
				}
			}
		}

	}
	return nil
}

func (c *ARPClient) arpProbe() error {

	// Copy underneath array so we can modify value.
	ip := net.ParseIP(c.config.HomeLAN.IP.String()).To4()

	log.Info("Discovering IP - sending 254 ARP requests")
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// err := ARPRequest(c.config.HostMAC, net.IPv4zero, ip) // Send ARP Probe
		log.Debugf("ARP probe ip %s", ip.String())
		err := c.request(c.config.HostMAC, c.config.HostIP, ip) // Request
		if err != nil {
			log.Error("Error ARP request: ", ip.String(), err)
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

// ARPSpoof send a gratuitous ARP packet to spoof client MAC table to send router packets to host instead of the router
// i.e.  192.168.0.1->RouterMAC becames 192.168.0.1->HostMAC
//
// Spoof only last for a short while (few minutes) hence the goroutine that re-arp clients
//
//
func (c *ARPClient) ARPSpoof(client *ARPEntry) error {

	ip := client.IP
	c.mutex.Lock()
	if client.State == ARPStateHunt {
		ip = client.PreviousIP
	}
	c.mutex.Unlock()

	log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": ip.String()}).Warn("ARP spoof client")

	for i := 0; i < 2; i++ {
		err := c.ARPReply(c.config.HostMAC, c.config.RouterIP, client.MAC, ip)
		if err != nil {
			log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": ip.String()}).Error("ARP spoof client error", err)
			return err
		}
		time.Sleep(time.Millisecond * 10)

		// NO NEED TO SPOOF THE ROUTER
		// err := ARPReply(c.config.HostMAC, config.HomeRouterIP, client.MAC, config.HomeRouterIP)
		// err = ARPReply(c.config.HostMAC, ip, client.MAC, config.HomeRouterIP)
		// if err != nil {
		// log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": ip.String()}).Error("ARP spoof router error", err)
		// return err
		// }
		// time.Sleep(time.Millisecond * 10)
	}

	return nil
}

// ARPIPChanged notify arp logic that the IP has changed.
// This is likely as a result of a DHCP change. Some clients do
// not send ARP Collision Detection packets and hence do not appear as an ARP change.
func (c *ARPClient) ARPIPChanged(clientHwAddr net.HardwareAddr, clientIP net.IP) {
	client := c.ARPFindMAC(clientHwAddr.String())
	if client == nil {
		log.WithFields(log.Fields{"clientmac": clientHwAddr, "clientip": clientIP}).Warn("ARP received new mac before arp packet")
		c.arpTableAppend(ARPStateNormal, clientHwAddr, clientIP)
		return
	}

	log.WithFields(log.Fields{"clientmac": clientHwAddr, "clientip": clientIP}).Info("ARP IP changed ")
	if client.State == ARPStateHunt {
		c.actionRequestInHuntState(client, clientIP, clientIP)
	} else {
		c.actionUpdateClient(client, client.MAC, clientIP)
	}
}

// ARPForceIPChange performs the following:
//  1. set client state to "capture" resetting the client IP in the process.
//  2. create a virtual host to handle the reallocated IP
//  3. spoof the client IP to redirect all traffic to host
//  4. set a callback when we receive a request from this client
//
// client will revert back to "normal" when a new IP is detected for the MAC
func (c *ARPClient) ARPForceIPChange(clientHwAddr net.HardwareAddr, clientIP net.IP,
	callback func(srcHwAddr net.HardwareAddr, srcIP net.IP)) error {
	log.WithFields(log.Fields{"clientmac": clientHwAddr.String(), "clientip": clientIP.String()}).Warn("ARP capture force IP change")

	client := c.ARPFindMAC(clientHwAddr.String())
	if client == nil {
		err := errors.New(fmt.Sprintf("ARP MAC not found"))
		log.Error("ARP unexpected error in force DHCP", err)
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
	virtual := c.arpTableAppend(ARPStateVirtualHost, ARPNewVirtualMAC(), clientIP)
	// virtual.callback = arpReplyVirtualMAC
	virtual.callback = nil

	// Set client state to capture and reset IP address
	c.mutex.Lock()
	client.callback = callback
	client.PreviousIP = net.ParseIP(client.IP.String()).To4()
	client.IP = net.IPv4zero
	client.State = ARPStateHunt
	c.mutex.Unlock()

	go func() {
		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": client.PreviousIP.String()}).Info("ARP hunt start")
		defer log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": client.PreviousIP.String()}).Info("ARP hunt end")

		for i := 0; i < 20; i++ {
			log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": virtual.IP}).Infof("ARP hunt claim IP %s", virtual.IP)
			if client.State != ARPStateHunt {
				return
			}
			c.ARPSpoof(client)

			// Send ARP announcement
			// ARPRequest(c.config.HostMAC, c.config.HostIP, arpClient.table[i].PreviousIP) // Request update

			// Send gratuitous reply
			virtual := c.ARPFindIP(client.PreviousIP)
			if virtual != nil {
				if client.State != ARPStateHunt {
					return
				}
				c.request(virtual.MAC, virtual.IP, virtual.IP) // Send ARP announcement

				time.Sleep(time.Millisecond * 30)
				// ARPReply(virtual.MAC, virtual.IP, arpClient.table[i].MAC, virtual.IP) // Send gratuitous ARP reply
				// Send ARP reply to broadcast MAC

				if client.State != ARPStateHunt {
					return
				}
				c.ARPReply(virtual.MAC, virtual.IP, EthernetBroadcast, virtual.IP) // Send gratuitous ARP reply
			}
			time.Sleep(time.Second * 4)
		}

		// Notify if channel given
		if c.tranChannel != nil {
			c.tranChannel <- *client
		}
		log.WithFields(log.Fields{"clientmac": client.MAC.String(), "virtualip": client.PreviousIP.String()}).Warn("ARP hunt failed")
		//actionStopHunt(client)
	}()
	// Redirect all client traffic to host
	// ARPSpoof(client)

	return nil
}

// ARPFakeConflict tricks clients to send a new DHCP request to capture the name.
// It is used to get the initial client name.
//
func (c *ARPClient) ARPFakeIPConflict(clientHwAddr net.HardwareAddr, clientIP net.IP) {
	log.WithFields(log.Fields{"clientmac": clientHwAddr.String(), "clientip": clientIP.String()}).Warn("ARP fake IP conflict")

	go func() {

		for i := 0; i < 7; i++ {
			c.request(c.config.HostMAC, clientIP, clientIP) // Send ARP announcement
			time.Sleep(time.Millisecond * 10)
			// ARPReply(virtual.MAC, virtual.IP, arpClient.table[i].MAC, virtual.IP) // Send gratuitous ARP reply
			// Send ARP reply to broadcast MAC

			c.ARPReply(c.config.HostMAC, clientIP, clientHwAddr, clientIP) // Send gratuitous ARP reply
		}
	}()
}

func (c *ARPClient) actionStopHunt(client *ARPEntry) {
	log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": client.PreviousIP.String()}).Info("ARP hunt stop")
	c.deleteVirtualMAC(client.PreviousIP)
	c.mutex.Lock()
	if client.State == ARPStateHunt {
		client.State = ARPStateNormal
		client.IP = client.PreviousIP
		client.PreviousIP = net.IPv4zero
	}
	c.mutex.Unlock()
}

func (c *ARPClient) actionUpdateClient(client *ARPEntry, senderMAC net.HardwareAddr, senderIP net.IP) {
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
		callback := client.callback
		client.State = ARPStateNormal
		c.mutex.Unlock()
		c.deleteVirtualMAC(virtual)

		if callback != nil {
			client.callback(client.MAC, client.IP)
		}
	}
}

func (c *ARPClient) actionRequestInHuntState(client *ARPEntry, senderIP net.IP, targetIP net.IP) (err error) {

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

		c.actionUpdateClient(client, client.MAC, targetIP)

		return
	}

	log.Warnf("ARP client attempting to get same IP previous %s new %s", client.PreviousIP, targetIP)

	err = c.actionClaimIP(client, client.MAC, targetIP)

	return err
}

func (c *ARPClient) actionClaimIP(client *ARPEntry, senderMAC net.HardwareAddr, senderIP net.IP) (err error) {

	ip := client.IP
	c.mutex.Lock()
	if client.State == ARPStateHunt {
		ip = client.PreviousIP
	}
	c.mutex.Unlock()

	log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": ip.String()}).Warnf("ARP capture claim %s", ip.String())

	// Re-arp client so all traffic comes to host
	// i.e. I am 192.168.0.1
	c.ARPSpoof(client)

	// Request ownership of the IP; this will force the client to acquire another IP
	// Gratuitous Request will have IP = zero
	virtual := c.ARPFindIP(ip)
	if virtual == nil || virtual.State != ARPStateVirtualHost {
		err = errors.New(fmt.Sprintf("cannot find virtual host for %s", ip.String()))
		log.Error("ARP error virtual host", err)
		return err
	}

	for i := 0; i < 3; i++ {
		/****
		  This causes a loop when the client is replying quickly
		  		err := ARPRequest(virtual.MAC, virtual.IP, virtual.IP) // Send ARP announcement
		  		if err != nil {
		  			log.WithFields(log.Fields{"clientmac": virtual.MAC.String(), "clientip": virtual.IP.String()}).Error("ARP error send announcement packet", err)
		  			return err
		  		}
		  		time.Sleep(time.Millisecond * 4)
		  ****/
		c.ARPReply(virtual.MAC, virtual.IP, client.MAC, virtual.IP) // Send gratuitous ARP reply
		time.Sleep(time.Millisecond * 5)
		err = c.ARPReply(virtual.MAC, virtual.IP, EthernetBroadcast, virtual.IP) // Send gratuitous ARP reply

		if err != nil {
			log.WithFields(log.Fields{"clientmac": client.MAC.String(), "clientip": client.IP.String()}).Error("ARP error send gratuitous packet", err)
			return err
		}
		time.Sleep(time.Millisecond * 4)
	}

	return nil
}

func (c *ARPClient) arpTableAppend(state arpState, clientMAC net.HardwareAddr, clientIP net.IP) (ret *ARPEntry) {
	mac := dupMAC(clientMAC)    // copy the underlying slice
	ip := dupIP(clientIP).To4() // copy the underlysing slice

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
	if ret.State != ARPStateVirtualHost && c.notification != nil {
		c.notification <- *ret
	}

	c.ARPPrintTable()
	return ret
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

func (c *ARPClient) deleteVirtualMAC(ip net.IP) {
	virtual := c.ARPFindIP(ip)

	if virtual == nil || (virtual != nil && virtual.State != ARPStateVirtualHost) {
		//	log.Errorf("ARP error non-existent virtual IP %s", ip)
		return
	}

	virtual.State = ARPStateDeleted
	virtual.IP = net.IPv4zero
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
func (c *ARPClient) ARPListenAndServe() {

	// Set ZERO timeout to block forever
	if err := c.client.SetReadDeadline(time.Time{}); err != nil {
		log.Error("ARP error in socket:", err)
		return
	}

	// Loop and wait for replies
	for {
		// log.Debugf("ARP loop start ")

		packet, _, err := c.client.Read()
		if err != nil {
			log.Info("ARP error in read socket: ", err)
			time.Sleep(time.Millisecond * 30) // Wait a few seconds before retrying
			continue
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
				return
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

func dupIP(srcIP net.IP) net.IP {
	ip := make(net.IP, len(srcIP))
	copy(ip, srcIP)
	return ip
}

func dupMAC(srcMAC net.HardwareAddr) net.HardwareAddr {
	mac := make(net.HardwareAddr, len(srcMAC))
	copy(mac, srcMAC)
	return mac
}
