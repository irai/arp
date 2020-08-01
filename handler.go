package arp

import (
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
	PurgeInterval           time.Duration    `yaml:"-"`
}

// Handler stores instance variables
type Handler struct {
	client *marp.Client
	table  *arpTable
	config Config
	sync.RWMutex
	notification chan<- MACEntry // notification channel for state change
	ctx          context.Context // context to cancel internal goroutines
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
	c.config.HostIP = config.HostIP.To4()
	c.config.RouterIP = config.RouterIP.To4()
	c.config.HomeLAN = config.HomeLAN
	c.config.FullNetworkScanInterval = config.FullNetworkScanInterval
	c.config.OnlineProbeInterval = config.OnlineProbeInterval
	c.config.PurgeInterval = config.PurgeInterval

	if c.config.FullNetworkScanInterval <= 0 || c.config.FullNetworkScanInterval > time.Hour*12 {
		c.config.FullNetworkScanInterval = time.Minute * 60
	}
	if c.config.OnlineProbeInterval <= 0 || c.config.OnlineProbeInterval > time.Minute*5 {
		c.config.OnlineProbeInterval = time.Minute * 2
	}
	if c.config.PurgeInterval <= c.config.OnlineProbeInterval || c.config.PurgeInterval > time.Hour*3 {
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
	c.RLock()
	defer c.RUnlock()

	e := c.table.findByMAC(mac)
	if e == nil {
		return MACEntry{}, false
	}
	return *e, true
}

// PrintTable print the ARP table to stdout.
func (c *Handler) PrintTable() {
	c.RLock()
	defer c.RUnlock()

	log.Printf("ARP Table: %v entries", len(c.table.macTable))
	c.table.printTable()
}

// Close will terminate the ListenAndServer goroutine as well as all other pending goroutines.
func (c *Handler) Close() {
	// Close the arp socket
	c.client.Close()
}

// ListenAndServe listen for ARP packets and action each.
//
// parameters:
//   scanInterval - frequency to poll existing MACs to ensure they are online
//
// When a new MAC is detected, it is automatically added to the ARP table and marked as online.
// Use packet buffer and selectivelly copy mac and ip if we need to keep it
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
		if err := c.purgeLoop(c.ctx, c.config.OnlineProbeInterval*2, c.config.PurgeInterval); err != nil {
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
			wg.Wait()
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
			wg.Wait()
			return fmt.Errorf("ARP ListenAndServer terminated unexpectedly: %w", err)
		}

		notify := 0

		// skip link local packets
		if packet.SenderIP.IsLinkLocalUnicast() ||
			packet.TargetIP.IsLinkLocalUnicast() {
			if Debug {
				log.Debugf("ARP skipping link local packet smac=%v sip=%v tmac=%v tip=%v", packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)
			}
			continue
		}

		// Ignore ACD probes - if this is a probe, the sender IP will be Zeros
		// do nothing as the sender IP is not valid yet.
		if packet.Operation == marp.OperationRequest && packet.SenderIP.Equal(net.IPv4zero) {
			if Debug {
				log.Debugf("ARP acd probe received smac=%v sip=%v tmac=%v tip=%v", packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)
			}
			continue // continue the for loop
		}

		if Debug {
			switch {
			case packet.Operation == marp.OperationReply:
				log.Debugf("ARP reply received smac=%v sip=%v tmac=%v tip=%v", packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)
			case packet.Operation == marp.OperationReply:
				switch {
				case packet.SenderIP.Equal(packet.TargetIP):
					log.Debugf("ARP announcement received smac=%v sip=%v tmac=%v tip=%v", packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)
				default:
					log.Debugf("ARP request received smac=%v sip=%v tmac=%v tip=%v", packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)
				}
			}
		}

		c.Lock()

		sender := c.table.findByMAC(packet.SenderHardwareAddr)
		if sender == nil {
			// If new client, then create a MACEntry in table
			sender, _ = c.table.upsert(StateNormal, dupMAC(packet.SenderHardwareAddr), dupIP(packet.SenderIP))
			notify++
		} else {
			// notify online transition
			if sender.Online == false {
				notify++
			}
		}

		// Skip packets that we sent as virtual host (i.e. we sent these)
		if sender.State == StateVirtualHost {
			c.Unlock()
			continue
		}

		sender.LastUpdated = time.Now()

		switch packet.Operation {

		case marp.OperationRequest:

			// if target is virtual host, we are spoofing the ip; reply and return
			// search by IP
			if target := c.table.findVirtualIP(packet.TargetIP); target != nil {
				mac := target.MAC
				if Debug {
					log.Debugf("ARP sending reply for virtual ip=%s smac=%v sip=%v tmac=%v",
						packet.TargetIP, packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr)
				}
				c.Unlock()
				c.reply(mac, packet.TargetIP, EthernetBroadcast, packet.TargetIP)
				c.Lock()
				break // break the switch
			}

			switch sender.State {
			case StateHunt:
				// We are only interested in ARP Address Conflict Detection packets:
				//
				// +============+===+===========+===========+============+============+===================+===========+
				// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
				// +============+===+===========+===========+============+============+===================+===========+
				// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
				// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
				// +============+===+===========+===========+============+============+===================+===========+
				if packet.SenderIP.Equal(net.IPv4zero) || (!packet.SenderIP.Equal(net.IPv4zero) && !packet.SenderIP.Equal(packet.TargetIP)) {
					break // break the switch
				}

				if _, found := sender.updateIP(dupIP(packet.TargetIP)); found { // is this an existing IP?
					if Debug {
						log.WithFields(log.Fields{"mac": sender.MAC, "ip": packet.TargetIP}).Debugf("ARP client attempting to get same IP %s", packet.TargetIP)
					}
					break // break the switch
				}

				// This is a new address, stop hunting it. The spoof function will detect the mac changed to normal
				// and delete the virtual IP.
				//
				sender.State = StateNormal
				if Debug {
					log.Debugf("ARP client state=%v mac=%v updated IP to %s", StateHunt, sender.MAC, packet.TargetIP)
				}
				notify++

			case StateNormal:
				if packet.SenderIP.Equal(net.IPv4zero) { // ignore ACD probe
					break
				}
				if _, found := sender.updateIP(dupIP(packet.SenderIP)); !found {
					if Debug {
						log.Debugf("ARP client state=%v mac=%v updated IP to %s", sender.State, sender.MAC, packet.TargetIP)
					}
					notify++
				}

			default:
				log.Error("ARP unexpected client state in request =", sender.State)
			}

		case marp.OperationReply:
			// Android does not send collision detection request,
			// we will see a reply instead. Check if the address has changed.
			if !packet.SenderIP.Equal(net.IPv4zero) {
				if _, found := sender.updateIP(dupIP(packet.SenderIP)); !found {
					if Debug {
						log.Debugf("ARP client state=%v mac=%v updated reply IP to %s", sender.State, sender.MAC, packet.SenderIP)
					}
					if sender.State == StateHunt {
						sender.State = StateNormal
					}
					notify++
				}
			}
		}

		c.Unlock()

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
