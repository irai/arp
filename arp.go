package arp

import (
	"net"
	"time"

	marp "github.com/mdlayher/arp"
	log "github.com/sirupsen/logrus"
)

var (
	writeTimeout, _ = time.ParseDuration("100ms")
	scanTimeout, _  = time.ParseDuration("5s")

	// EthernetBroadcast defines the broadcast address
	EthernetBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

func (c *Handler) request(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	arp, err := marp.NewPacket(marp.OperationRequest, srcHwAddr, srcIP, dstHwAddr, dstIP)
	if err != nil {
		return err
	}

	if err := c.client.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}

	return c.client.WriteTo(arp, EthernetBroadcast)
}

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
			log.WithFields(log.Fields{"srcmac": srcHwAddr, "srcip": srcIP, "dstmac": dstHwAddr, "dstip": dstIP}).Debugf("ARP send announcement - I am %s", dstIP)
		} else {
			log.WithFields(log.Fields{"srcmac": srcHwAddr, "srcip": srcIP, "dstmac": dstHwAddr, "dstip": dstIP}).Debugf("ARP send request - who is %s", dstIP)
		}
	}

	return c.request(srcHwAddr, srcIP, dstHwAddr, dstIP)
}

// Reply send ARP reply from the src to the dst
//
// Call with dstHwAddr = ethernet.Broadcast to reply to all
func (c *Handler) Reply(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	if Debug {
		log.WithFields(log.Fields{"dstmac": dstHwAddr.String(), "dstip": dstIP.String()}).Debugf("ARP send reply - host %s is at %s", srcIP.String(), srcHwAddr.String())
	}
	return c.reply(srcHwAddr, srcIP, dstHwAddr, dstIP)
}

func (c *Handler) reply(srcHwAddr net.HardwareAddr, srcIP net.IP, dstHwAddr net.HardwareAddr, dstIP net.IP) error {
	p, err := marp.NewPacket(marp.OperationReply, srcHwAddr, srcIP, dstHwAddr, dstIP)
	if err != nil {
		return err
	}

	if err := c.client.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}

	return c.client.WriteTo(p, dstHwAddr)
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
	return c.announceUnicast(mac, ip, EthernetBroadcast)
}

func (c *Handler) announceUnicast(mac net.HardwareAddr, ip net.IP, targetMac net.HardwareAddr) (err error) {
	err = c.Request(mac, ip, targetMac, ip)
	go func() {
		time.Sleep(time.Second * 1)
		c.request(mac, ip, targetMac, ip)
		time.Sleep(time.Second * 1)
	}()
	return err
}

// WhoIs will send a request packet to get the MAC address for the IP. Retry 3 times.
//
func (c *Handler) WhoIs(ip net.IP) (MACEntry *MACEntry, err error) {
	c.RLock()

	// test first before sending request; useful for testing
	if MACEntry = c.table.findByIP(ip); MACEntry != nil {
		c.RUnlock()
		return MACEntry, nil
	}
	c.RUnlock()

	for i := 0; i < 3; i++ {
		c.Request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, ip)
		time.Sleep(time.Millisecond * 50)
		if MACEntry = c.table.findByIP(ip); MACEntry != nil {
			return MACEntry, nil
		}
	}
	return nil, nil
}
