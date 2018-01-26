package main

import (
	"flag"
	log "github.com/sirupsen/logrus"
	"net"
	"spinifex/base"
	"spinifex/netfilter/db"
	"spinifex/network/arp"
	"time"
)

var (
	// durFlag is used to set a timeout for an ARP request
	durFlag = flag.Duration("d", 1*time.Millisecond, "timeout for ARP request")

	// ifaceFlag is used to set a network interface for ARP requests
	ifaceFlag = flag.String("i", "eth0", "network interface to use for ARP request")

	// ipFlag is used to set an IPv4 address destination for an ARP request
	ipFlag = flag.String("ip", "", "IPv4 address destination for ARP request")

	CIDRFlag = flag.String("cidr", "", "CIDR destination to probe with ARP request")

	srcIPFlag = flag.String("sip", "", "src IP for reply packet i.e -sip 192.168.0.10. ARP poisoning")

	srcMACFlag = flag.String("smac", "", "src MAC for reply packet i.e -mac 6e:a7:e6:d6:f9:a4 . ARP poisoning")

	dstIPFlag = flag.String("dip", "", "dst IP for reply packet i.e -sip 192.168.0.10. ARP poisoning")

	dstMACFlag = flag.String("dmac", "", "dst MAC for reply packet i.e -mac 6e:a7:e6:d6:f9:a4 . ARP poisoning")
)

// LeaseTable contains the IPs allocated by our DHCP server
var LeaseTable map[string]arp.ARPEntry = make(map[string]arp.ARPEntry)

func main() {
	flag.Parse()

	base.SetLogLevel("debug")

	config := &db.Config{}
	config.NIC = *ifaceFlag

	var err error
	config.HostIP, config.HostMAC, err = network.NICGetInformation(config.NIC)
	if err != nil {
		log.Fatal("error cannot get host ip and mac ", err)
	}

	config.HomeLAN = net.IPNet{IP: net.ParseIP("192.168.0.0").To4(), Mask: net.CIDRMask(25, 32)}
	config.HomeRouterIP = net.ParseIP("192.168.0.1").To4()

	config.NetfilterLAN = net.IPNet{IP: net.ParseIP("192.168.0.128").To4(), Mask: net.CIDRMask(25, 32)}
	config.NetfilterRouter = net.ParseIP("192.168.0.129").To4()

	c, err := arp.NewARPClient(config.NIC, config.HostMAC, config.HostIP, config.RouterIP, config.HomeLAN)
	if err != nil {
		log.Fatal("error connection to websocket server", err)
	}

	go c.ARPListenAndServe()

	c.ARPProbeLoop(time.Second * 30 * 5)

}
