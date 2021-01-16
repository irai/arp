package arp

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"errors"
	"log"

	marp "github.com/mdlayher/arp"
)

var (
	// ErrNotFound is returned when MAC not found
	ErrNotFound = errors.New("not found")

	writeTimeout, _ = time.ParseDuration("100ms")
	scanTimeout, _  = time.ParseDuration("5s")

	// EthernetBroadcast defines the broadcast address
	EthernetBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

// Request send ARP request from src to dst
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
func (c *Handler) Request(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	if Debug {
		if srcIP.Equal(dstIP) {
			log.Printf("ARP send announcement - I am ip=%s mac=%s", srcIP, srcHwAddr)
		} else {
			log.Printf("ARP send request - who is ip=%s tell sip=%s smac=%s", dstIP, srcIP, srcHwAddr)
		}
	}

	return c.requestWithDstEthernet(EthernetBroadcast, srcHwAddr, srcIP, dstHwAddr, dstIP)
}

func (c *Handler) request(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	return c.requestWithDstEthernet(EthernetBroadcast, srcHwAddr, srcIP, dstHwAddr, dstIP)
}

func (c *Handler) requestWithDstEthernet(dstEther net.HardwareAddr, srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	arp, err := marp.NewPacket(marp.OperationRequest, srcHwAddr, srcIP, dstHwAddr, dstIP)
	if err != nil {
		return err
	}

	if err := c.client.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}

	return c.client.WriteTo(arp, dstEther)
}

// Reply send ARP reply from the src to the dst
//
// Call with dstHwAddr = ethernet.Broadcast to reply to all
func (c *Handler) Reply(dstEther net.HardwareAddr, srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	if Debug {
		log.Printf("ARP send reply - ip=%s is at mac=%s", srcIP, srcHwAddr)
	}
	return c.reply(dstEther, srcHwAddr, srcIP, dstHwAddr, dstIP)
}

// reply sends a ARP reply packet from src to dst.
//
// dstEther identifies the target for the Ethernet packet : i.e. use EthernetBroadcast for gratuitous ARP
func (c *Handler) reply(dstEther net.HardwareAddr, srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	p, err := marp.NewPacket(marp.OperationReply, srcHwAddr, srcIP, dstHwAddr, dstIP)
	if err != nil {
		return err
	}

	if err := c.client.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}

	return c.client.WriteTo(p, dstEther)
}

// Probe will send an arp request broadcast on the local link.
//
// The term 'ARP Probe' is used to refer to an ARP Request packet, broadcast on the local link,
// with an all-zero 'sender IP address'. The 'sender hardware address' MUST contain the hardware address of the
// interface sending the packet. The 'sender IP address' field MUST be set to all zeroes,
// to avoid polluting ARP caches in other hosts on the same link in the case where the address turns out
// to be already in use by another host. The 'target IP address' field MUST be set to the address being probed.
// An ARP Probe conveys both a question ("Is anyone using this address?") and an
// implied statement ("This is the address I hope to use.").
func (c *Handler) Probe(ip net.IP) error {
	return c.Request(c.config.HostMAC, net.IPv4zero, EthernetBroadcast, ip)
}

// probeUnicast is used to validate the client is still online; same as ARP probe but unicast to target
func (c *Handler) probeUnicast(mac net.HardwareAddr, ip net.IP) error {
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
func (c *Handler) announce(mac net.HardwareAddr, ip net.IP) error {
	return c.announceWithDstEthernet(EthernetBroadcast, mac, ip, EthernetBroadcast)
}

func (c *Handler) announceWithDstEthernet(dstEther net.HardwareAddr, mac net.HardwareAddr, ip net.IP, targetMac net.HardwareAddr) (err error) {
	if Debug {
		if bytes.Equal(dstEther, EthernetBroadcast) {
			log.Printf("ARP send announcement - I am ip=%s mac=%s", ip, mac)
		} else {
			log.Printf("ARP send announcement unicast - I am ip=%s mac=%s to=%s", ip, mac, dstEther)
		}
	}
	err = c.requestWithDstEthernet(dstEther, mac, ip, targetMac, ip)
	go func() {
		time.Sleep(time.Second * 1)
		c.requestWithDstEthernet(dstEther, mac, ip, targetMac, ip)
		time.Sleep(time.Second * 1)
		c.requestWithDstEthernet(dstEther, mac, ip, targetMac, ip)
	}()
	return err
}

func (c *Handler) announceUnicast(dstEther net.HardwareAddr, mac net.HardwareAddr, ip net.IP) (err error) {
	return c.announceWithDstEthernet(dstEther, mac, ip, dstEther)
}

// WhoIs will send a request packet to get the MAC address for the IP. Retry 3 times.
//
func (c *Handler) WhoIs(ip net.IP) (MACEntry, error) {

	// test first before sending request; useful for testing
	c.RLock()
	if e := c.table.findByIP(ip); e != nil {
		entry := *e
		c.RUnlock()
		return entry, nil
	}
	c.RUnlock()

	for i := 0; i < 3; i++ {
		if err := c.Request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, ip); err != nil {
			return MACEntry{}, fmt.Errorf("ARP WhoIs error: %w", err)
		}
		time.Sleep(time.Millisecond * 50)

		c.RLock()
		if e := c.table.findByIP(ip); e != nil {
			c.RUnlock()
			return *e, nil
		}
		c.RUnlock()
	}

	// hack to return routerMAC
	// need a better way to do this without including it in the table!!!
	if ip.Equal(c.config.RouterIP) && c.routerEntry.MAC != nil {
		return c.routerEntry, nil
	}

	if Debug {
		log.Printf("ARP ip=%s whois not found", ip)
		c.RLock()
		c.table.printTable()
		c.RUnlock()
	}
	return MACEntry{}, ErrNotFound
}
