package arp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"log"

	marp "github.com/mdlayher/arp"
)

// Config holds configuration parameters
type Config struct {
	NIC                     string           `yaml:"-"`
	HostMAC                 net.HardwareAddr `yaml:"-"`
	HostIP                  net.IP           `yaml:"-"`
	RouterIP                net.IP           `yaml:"-"`
	HomeLAN                 net.IPNet        `yaml:"-"`
	FullNetworkScanInterval time.Duration    `yaml:"-"`
	ProbeInterval           time.Duration    `yaml:"-"` // how often to probe if IP is online
	OfflineDeadline         time.Duration    `yaml:"-"` // mark offline if more than OfflineInte
	PurgeDeadline           time.Duration    `yaml:"-"`
}

func (c Config) String() string {
	return fmt.Sprintf("hostmac=%s hostIP=%s routerIP=%s homeLAN=%s scan=%v probe=%s offline=%v purge=%v",
		c.HostMAC, c.HostIP, c.RouterIP, c.HomeLAN, c.FullNetworkScanInterval, c.ProbeInterval, c.OfflineDeadline, c.PurgeDeadline)
}

// Handler stores instance variables
type Handler struct {
	client      *marp.Client
	table       *arpTable
	config      Config
	routerEntry MACEntry // store the router mac address
	sync.RWMutex
	notification chan<- MACEntry // notification channel for state change
	ctx          context.Context // context to cancel internal goroutines
}

var (
	// Debug - set Debug to true to see debugging messages
	Debug bool
)

// New creates an ARP handler for a given interface.
func New(config Config) (c *Handler, err error) {
	c = newHandler(config)

	ifi, err := net.InterfaceByName(config.NIC)
	if err != nil {
		return nil, fmt.Errorf("InterfaceByName error: %w", err)
	}

	// Set up ARP client with socket
	c.client, err = marp.Dial(ifi)
	if err != nil {
		return nil, fmt.Errorf("ARP dial error: %w", err)
	}

	return c, nil
}

func newHandler(config Config) (c *Handler) {
	c = &Handler{}
	c.table = newARPTable()
	c.config.NIC = config.NIC
	c.config.HostMAC = config.HostMAC
	c.config.HostIP = config.HostIP.To4()
	c.config.RouterIP = config.RouterIP.To4()
	c.config.HomeLAN = config.HomeLAN
	c.config.FullNetworkScanInterval = config.FullNetworkScanInterval
	c.config.ProbeInterval = config.ProbeInterval
	c.config.OfflineDeadline = config.OfflineDeadline
	c.config.PurgeDeadline = config.PurgeDeadline

	if c.config.FullNetworkScanInterval <= 0 || c.config.FullNetworkScanInterval > time.Hour*12 {
		c.config.FullNetworkScanInterval = time.Minute * 60
	}
	if c.config.ProbeInterval <= 0 || c.config.ProbeInterval > time.Minute*10 {
		c.config.ProbeInterval = time.Minute * 2
	}
	if c.config.OfflineDeadline <= c.config.ProbeInterval {
		c.config.OfflineDeadline = c.config.ProbeInterval * 2
	}
	if c.config.PurgeDeadline <= c.config.OfflineDeadline {
		c.config.PurgeDeadline = time.Minute * 61
	}

	if Debug {
		log.Printf("ARP Config %s", c.config)
	}

	return c
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

// GetTable return the mac table as a shallow array of MACEntry
func (c *Handler) GetTable() []MACEntry {
	return c.table.getTable()
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
			log.Print("ARP goroutine scanLoop terminated unexpectedly", err)
		}
		wg.Done()
		c.Close()
		if Debug {
			log.Print("ARP goroutine scanLoop ended")
		}
	}()

	// continously probe for online reply
	go func() {
		wg.Add(1)
		if err := c.probeOnlineLoop(c.ctx, c.config.ProbeInterval); err != nil {
			log.Print("ARP goroutine probeOnlineLoop terminated unexpectedly", err)
		}
		wg.Done()
		c.Close()
		if Debug {
			log.Print("ARP goroutine probeOnlineLoop ended")
		}
	}()

	// continously check for online-offline transition
	go func() {
		wg.Add(1)
		if err := c.purgeLoop(c.ctx, c.config.OfflineDeadline, c.config.PurgeDeadline); err != nil {
			log.Print("ARP ListenAndServer purgeLoop terminated unexpectedly", err)
		}
		wg.Done()
		c.Close()
		if Debug {
			log.Print("ARP goroutine purgeLoop ended")
		}
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
			if Debug {
				log.Print("ARP goroutine purgeLoop ended")
			}
			return nil
		}
		if err != nil {
			// "interrupted system call" occurs frequently after go 1.14
			// simply retry - don't wait
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				// log.Print("ARP read error is temporary - retry ", err1)
				continue
			}
			if Debug {
				log.Print("ARP read error ", err)
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
				log.Printf("ARP skipping link local packet smac=%v sip=%v tmac=%v tip=%v", packet.SenderHardwareAddr, packet.SenderIP, packet.TargetHardwareAddr, packet.TargetIP)
			}
			continue
		}

		if Debug {
			switch {
			case packet.Operation == marp.OperationReply:
				log.Printf("ARP ip=%s reply recvd smac=%s tmac=%s tip=%s", packet.SenderIP, packet.SenderHardwareAddr, packet.TargetHardwareAddr, packet.TargetIP)
			case packet.Operation == marp.OperationRequest:
				switch {
				case packet.SenderIP.Equal(packet.TargetIP):
					log.Printf("ARP ip=%s announcement recvd smac=%s tmac=%s tip=%s", packet.SenderIP, packet.SenderHardwareAddr, packet.TargetHardwareAddr, packet.TargetIP)
				case packet.SenderIP.Equal(net.IPv4zero):
					log.Printf("ARP ip=%s probe recvd for tip=%s smac=%s tmac=%s", packet.SenderIP, packet.TargetIP, packet.SenderHardwareAddr, packet.TargetHardwareAddr)
				default:
					log.Printf("ARP ip=%s who is tip=%s smac=%v tmac=%v", packet.SenderIP, packet.TargetIP, packet.SenderHardwareAddr, packet.TargetHardwareAddr)
				}
			default:
				log.Printf("ARP invalid operation=%v packet=%+v", packet.Operation, packet)
				continue
			}
		}

		// Ignore router packets
		if bytes.Equal(packet.SenderIP, c.config.RouterIP) {
			if c.routerEntry.MAC == nil { // store router MAC
				c.routerEntry.MAC = dupMAC(packet.SenderHardwareAddr)
				c.routerEntry.ipArray[0] = IPEntry{IP: c.config.RouterIP}
			}
			continue
		}

		// Ignore host packets
		if bytes.Equal(packet.SenderHardwareAddr, c.config.HostMAC) {
			continue
		}

		// if targetIP is a virtual host, we are claiming the ip; reply and return
		c.RLock()
		if target := c.table.findVirtualIP(packet.TargetIP); target != nil {
			mac := target.MAC
			c.RUnlock()
			if Debug {
				log.Printf("ARP ip=%s is virtual - send announcement smac=%v", packet.TargetIP, mac)
			}
			c.reply(mac, packet.TargetIP, EthernetBroadcast, packet.TargetIP)
			continue
		}
		c.RUnlock()

		// We are not interested in probe ACD (Address Conflict Detection) packets
		// if this is a probe, the sender IP will be zeros; do nothing as the sender IP is not valid yet.
		//
		// +============+===+===========+===========+============+============+===================+===========+
		// | Type       | op| dstMAC    | srcMAC    | SenderMAC  | SenderIP   | TargetMAC         |  TargetIP |
		// +============+===+===========+===========+============+============+===================+===========+
		// | ACD probe  | 1 | broadcast | clientMAC | clientMAC  | 0x00       | 0x00              |  targetIP |
		// | ACD announ | 1 | broadcast | clientMAC | clientMAC  | clientIP   | ff:ff:ff:ff:ff:ff |  clientIP |
		// +============+===+===========+===========+============+============+===================+===========+
		if packet.SenderIP.Equal(net.IPv4zero) {
			continue
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

			switch sender.State {
			case StateHunt:

				// If this is a new IP, stop hunting it.
				// The spoof goroutine will detect the mac changed to normal and terminate.
				if !sender.updateIP(dupIP(packet.SenderIP)) {
					sender.State = StateNormal
					notify++
				}

			case StateNormal:
				if !sender.updateIP(dupIP(packet.SenderIP)) {
					notify++
				}

			default:
				log.Print("ARP unexpected client state in request =", sender.State)
			}

		case marp.OperationReply:
			// Android does not send collision detection request,
			// we will see a reply instead. Check if the address has changed.
			if !sender.updateIP(dupIP(packet.SenderIP)) {
				sender.State = StateNormal // will end hunt goroutine
				notify++
			}
		}

		if notify > 0 {
			if sender.Online == false {
				sender.Online = true
				log.Printf("ARP ip=%s is online mac=%s state=%s ips=%s", packet.SenderIP, sender.MAC, sender.State, sender.IPs())
			} else {
				log.Printf("ARP ip=%s is online - updated ip for mac=%s state=%s ips=%s", packet.SenderIP, sender.MAC, sender.State, sender.IPs())
			}

			if c.notification != nil {
				c.notification <- *sender
			}
		}

		c.Unlock()
	}
}
