package arp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	marp "github.com/mdlayher/arp"
	log "github.com/sirupsen/logrus"
)

// Config holds configuration parameters
type Config struct {
	NIC                     string           `yaml:"-"`
	HostMAC                 net.HardwareAddr `yaml:"-"`
	HostIP                  net.IP           `yaml:"-"`
	RouterIP                net.IP           `yaml:"-"`
	RouterMAC               net.HardwareAddr `yaml:"-"`
	HomeLAN                 net.IPNet        `yaml:"-"`
	FullNetworkScanInterval time.Duration    `yaml:"-"`
	OnlineProbeInterval     time.Duration    `yaml:"-"`
}

// Handler is used to handle ARP packets for a given interface.
type Handler struct {
	client       *marp.Client
	table        *arpTable
	notification chan<- MACEntry // notification channel for state change
	config       Config
	sync.RWMutex
	ctx context.Context // context to cancel internal goroutines
}

var (
	// Debug - set Debug to true to see debugging messages
	Debug bool
)

// NewHandler creates an ARP handler for a given interface.
func NewHandler(config Config) (c *Handler, err error) {
	c = &Handler{}
	ifi, err := net.InterfaceByName(config.NIC)
	if err != nil {
		return nil, fmt.Errorf("InterfaceByName error: %w", err)
	}

	// Set up ARP client with socket
	c.client, err = marp.Dial(ifi)
	if err != nil {
		return nil, fmt.Errorf("ARP dial error: %w", err)
	}

	c.table = newARPTable()
	c.config.NIC = config.NIC
	c.config.HostMAC = config.HostMAC
	c.config.HostIP = config.HostIP
	c.config.RouterIP = config.RouterIP
	c.config.HomeLAN = config.HomeLAN
	c.config.FullNetworkScanInterval = config.FullNetworkScanInterval
	c.config.OnlineProbeInterval = config.OnlineProbeInterval

	if c.config.FullNetworkScanInterval <= 0 || c.config.FullNetworkScanInterval > time.Hour*12 {
		c.config.FullNetworkScanInterval = time.Minute * 60
	}
	if c.config.OnlineProbeInterval <= 0 || c.config.OnlineProbeInterval > time.Minute*5 {
		c.config.OnlineProbeInterval = time.Minute * 2
	}

	if Debug {
		log.WithFields(log.Fields{"hostinterface": c.config.NIC, "hostmac": c.config.HostMAC.String(),
			"hostip": c.config.HostIP.String(), "lanrouter": c.config.RouterIP.String()}).Debug("ARP Config")
	}

	return c, nil
}

// AddNotificationChannel set the notification channel for when the MACEntry
// change state between online and offline.
func (c *Handler) AddNotificationChannel(notification chan<- MACEntry) {
	c.notification = notification

	c.Lock()
	table := c.table.getTable()
	c.Unlock()
	go func() {
		for i := range table {
			c.notification <- table[i]
		}
	}()
}

// FindMAC returns a MACEntry or nil if not found
func (c *Handler) FindMAC(mac net.HardwareAddr) (entry MACEntry, found bool) {
	e := c.table.findByMAC(mac)
	if e == nil {
		return MACEntry{}, false
	}
	return *e, true
}

// PrintTable will print the ARP table to stdout.
func (c *Handler) PrintTable() {
	log.Infof("ARP Table: %v entries", len(c.table.macTable))

	// Don't lock; it is called from multiple locked locations
	table := c.table.macTable
	for _, v := range table {
		log.WithFields(log.Fields{"mac": v.MAC, "ip": v.IPs}).Infof("ARP table %s", v)
	}
}

// Close will terminate the ListenAndServer goroutine as well as all other pending goroutines.
func (c *Handler) Close() {
	// Close the arp socket
	c.client.Close()
}

func (c *Handler) updateClient(client *MACEntry, senderMAC net.HardwareAddr, senderIP net.IP) int {
	// Update IP if client changed
	//
	// Ignore if same IP and client is Online
	// Ignore any router updates
	//
	if (client.findIP(senderIP) != nil && client.Online) ||
		senderIP.Equal(net.IPv4zero) ||
		bytes.Equal(senderMAC, c.config.RouterMAC) ||
		senderIP.Equal(c.config.HostIP) {
		return 0
	}

	c.Lock()
	client.updateIP(dupIP(senderIP))
	c.Unlock()

	if Debug {
		log.WithFields(log.Fields{"mac": client.MAC.String(), "ips": client.IPs}).Debugf("ARP client updated IP to %s", senderIP)
	}

	return 1
}

// actionRequestInHuntState respond to a request from a device that is in Hunt state.
//
// We are only interested in ARP Address Conflict Detection packets:
//
// +============+===+===========+===========+============+============+===================+===========+
// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
// +============+===+===========+===========+============+============+===================+===========+
// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
// +============+===+===========+===========+============+============+===================+===========+
func (c *Handler) processRequestInHuntState(client *MACEntry, senderIP net.IP, targetIP net.IP) (n int, err error) {

	if senderIP.Equal(net.IPv4zero) || (!senderIP.Equal(net.IPv4zero) && !senderIP.Equal(targetIP)) {
		return 0, nil
	}

	if Debug {
		log.WithFields(log.Fields{"mac": client.MAC, "ip": targetIP}).Debugf("ARP client announcement in hunt state %s", targetIP)
	}

	if _, found := client.updateIP(targetIP); found { // is this an existing IP?
		if Debug {
			log.WithFields(log.Fields{"mac": client.MAC, "ip": targetIP}).Debugf("ARP client attempting to get same IP %s", targetIP)
		}
		return 0, fmt.Errorf("error updating client: %s, %v ", client.MAC, targetIP)
	}

	// This is a new address, stop hunting it. The spoof function will detect the mac changed to normal
	// and delete the virtual IP.
	//
	client.State = StateNormal

	if Debug {
		log.WithFields(log.Fields{"mac": client.MAC.String(), "ips": client.IPs}).Debugf("ARP client updated IP to %s", senderIP)
	}

	return 0, err
}

// ListenAndServe listen for ARP packets and action these.
//
// parameters:
//   scanInterval - frequency to poll existing MACs to ensure they are online
//
// When a new MAC is detected, it is automatically added to the ARP table and marked as online.
//
// Online and offline notifications
// It will track when a MAC switch between online and offline and will send a message
// in the notification channel set via AddNotificationChannel(). It will poll each known device
// based on the scanInterval parameter using a unicast ARP request.
//
//
// Virtual MACs
// A virtual MAC is a fake mac address used when claiming an existing IP during spoofing.
// ListenAndServe will send ARP reply on behalf of virtual MACs
//
func (c *Handler) ListenAndServe(ctx context.Context) error {

	var wg sync.WaitGroup

	// Set ZERO timeout to block forever
	if err := c.client.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("ARP error in socket: %w", err)
	}

	myctx, cancel := context.WithCancel(ctx)
	c.ctx = myctx

	// to continuosly scan for network devices
	go func() {
		wg.Add(1)
		if err := c.scanLoop(c.ctx, c.config.FullNetworkScanInterval); err != nil {
			log.Error("ARP ListenAndServer scanLoop terminated unexpectedly", err)
		}
		wg.Done()
	}()

	// continously probe for online reply
	go func() {
		wg.Add(1)
		if err := c.probeOnlineLoop(c.ctx, c.config.OnlineProbeInterval); err != nil {
			log.Error("ARP ListenAndServer probeOnlineLoop terminated unexpectedly", err)
		}
		wg.Done()
	}()

	// continously check for online-offline transition
	go func() {
		wg.Add(1)
		if err := c.purgeLoop(c.ctx, c.config.OnlineProbeInterval*2); err != nil {
			log.Error("ARP ListenAndServer purgeLoop terminated unexpectedly", err)
		}
		wg.Done()
	}()

	go func() {
		time.Sleep(time.Millisecond * 100) // Time to start read loop below
		c.ScanNetwork(c.ctx, c.config.HomeLAN)
	}()

	// Loop and wait for ARP packets
	for {
		packet, _, err := c.client.Read()
		if ctx.Err() != nil {
			cancel()
			return nil
		}
		if err != nil {
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				if Debug {
					log.Debug("ARP read error is temporary - retry", err1)
				}
				time.Sleep(time.Millisecond * 30) // Wait a few seconds before retrying
				continue
			}
			if Debug {
				log.Error("ARP read error ", err)
			}
			cancel()
			return fmt.Errorf("ARP ListenAndServer terminated unexpectedly: %w", err)
		}

		notify := 0

		// skip link local packets
		if packet.SenderIP.IsLinkLocalUnicast() ||
			packet.TargetIP.IsLinkLocalUnicast() {
			if Debug {
				log.WithFields(log.Fields{"senderip": packet.SenderIP, "targetip": packet.TargetIP}).Debug("ARP skipping link local packet")
			}
			continue
		}

		c.Lock()

		sender := c.table.findByMAC(packet.SenderHardwareAddr)
		if sender == nil {
			// If new client, then create a new MACEntry in table
			//
			// NOTE: if this is a probe, the sender IP will be Zeros
			//       do nothing as the sender IP is not valid yet.
			//
			if packet.Operation == marp.OperationRequest && packet.SenderIP.Equal(net.IPv4zero) {
				c.Unlock()

				if Debug {
					log.WithFields(log.Fields{"sendermac": packet.SenderHardwareAddr, "senderip": packet.SenderIP, "targetip": packet.TargetIP}).
						Debug("ARP acd probe received")
				}
				continue // continue the for loop
			}

			sender, _ = c.table.upsert(StateNormal, dupMAC(packet.SenderHardwareAddr), dupIP(packet.SenderIP))
			notify++
		}

		// Skip packets that we sent as virtual host (i.e. we sent these)
		if sender.State == StateVirtualHost {
			c.Unlock()
			continue
		}

		sender.LastUpdated = time.Now()

		c.Unlock()

		switch packet.Operation {

		// Reply to ARP request if we are spoofing this host.
		//
		case marp.OperationRequest:
			if Debug {
				if packet.SenderIP.Equal(packet.TargetIP) {
					log.WithFields(log.Fields{"mac": sender.MAC, "ip": packet.SenderIP, "state": sender.State}).Debug("ARP announcement received")
				} else {
					log.WithFields(log.Fields{"ip": packet.SenderIP, "mac": sender.MAC, "state": sender.State,
						"to_ip": packet.TargetIP.String(), "to_mac": packet.TargetHardwareAddr}).Debugf("ARP request received - who is %s tell %s", packet.TargetIP.String(), packet.SenderIP)
				}
			}

			// if target is virtual host, reply and return
			// search by IP
			if target := c.table.findVirtualIP(packet.TargetIP); target != nil {
				if Debug {
					log.WithFields(log.Fields{"ip": packet.TargetIP, "mac": target.MAC}).Debug("ARP sending reply for virtual mac")
				}
				c.reply(target.MAC, packet.TargetIP, EthernetBroadcast, packet.TargetIP)
				break // break the switch
			}

			switch sender.State {
			case StateHunt:
				n, _ := c.processRequestInHuntState(sender, packet.SenderIP, packet.TargetIP)
				notify = notify + n

			case StateNormal:
				notify += c.updateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)

			default:
				log.Error("ARP unexpected client state in request =", sender.State)
			}

		case marp.OperationReply:
			if Debug {
				log.WithFields(log.Fields{
					"ip": packet.SenderIP, "mac": sender.MAC, "state": sender.State,
					"senderip": packet.SenderIP.String(), "to_mac": packet.TargetHardwareAddr, "to_ip": packet.TargetIP}).
					Debugf("ARP reply received - %s is at %s", packet.SenderIP, sender.MAC)
			}

			switch sender.State {
			case StateNormal:
				_, found := sender.updateIP(dupIP(packet.SenderIP))
				if !found {
					if Debug {
						log.WithFields(log.Fields{"mac": sender.MAC, "ip": packet.SenderIP}).Debugf("ARP client updated reply IP to %s", packet.SenderIP)
					}
					notify++
				}
				// notify += c.actionUpdateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)

			case StateHunt:
				// Android does not send collision detection request,
				// we will see a reply instead. Check if the address has changed.
				if !packet.SenderIP.Equal(net.IPv4zero) {
					if _, found := sender.updateIP(dupIP(packet.SenderIP)); !found {
						notify++
					}
				}
				// notify += c.actionUpdateClient(sender, packet.SenderHardwareAddr, packet.SenderIP)

			default:
				log.WithFields(log.Fields{"ip": packet.SenderIP, "mac": sender.MAC}).Error("ARP unexpected client state in reply =", sender.State)
			}

		}

		if notify > 0 {
			if sender.Online == false {
				sender.Online = true
				log.WithFields(log.Fields{"mac": sender.MAC, "ip": packet.SenderIP, "state": sender.State}).Info("ARP device is online")
			} else {
				log.WithFields(log.Fields{"mac": sender.MAC, "ip": packet.SenderIP, "state": sender.State}).Info("ARP device changed IP")
			}

			if c.notification != nil {
				c.notification <- *sender
			}
		}
	}
}
