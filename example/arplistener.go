package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/irai/arp"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	// "spinifex/base"
	"strings"
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

func main() {
	flag.Parse()

	SetLogLevel("debug")

	NIC := *ifaceFlag

	var err error
	HostIP, HostMAC, err := NICGetInformation(NIC)
	if err != nil {
		log.Fatal("error cannot get host ip and mac ", err)
	}

	HomeLAN := net.IPNet{IP: net.ParseIP("192.168.0.0").To4(), Mask: net.CIDRMask(25, 32)}
	HomeRouterIP := net.ParseIP("192.168.0.1").To4()

	// NetfilterLAN := net.IPNet{IP: net.ParseIP("192.168.0.128").To4(), Mask: net.CIDRMask(25, 32)}
	// NetfilterRouter := net.ParseIP("192.168.0.129").To4()

	c, err := arp.NewARPClient(NIC, HostMAC, HostIP, HomeRouterIP, HomeLAN)
	if err != nil {
		log.Fatal("error connection to websocket server", err)
	}

	go c.ARPListenAndServe(time.Second * 30 * 5)

	c.ARPPrintTable()
	cmd(c)

	c.Stop()

}

func getMAC(c *arp.ARPClient, text string) *arp.ARPEntry {
	if len(text) <= 3 {
		log.Error("Invalid MAC")
		return nil
	}
	mac, err := net.ParseMAC(text[2:])
	if err != nil {
		log.Error("invalid MAC ", err)
		return nil
	}
	entry := c.ARPFindMAC(mac.String())
	if entry == nil {
		log.Error("Mac not found: ", mac)
		return nil
	}
	return entry
}

func cmd(c *arp.ARPClient) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit | (l)ist | (f)force <mac> | (s) stop <mac> | (g) loG <level>")
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		text = strings.ToLower(text[:len(text)-1])
		fmt.Println(text)

		if text == "" || len(text) < 1 {
			continue
		}

		switch text[0] {
		case 'q':
			return
		case 'g':
			if len(text) < 3 {
				log.Error("Invalid level")
				break
			}
			err := SetLogLevel(text[2:])
			if err != nil {
				log.Error("invalid level (fatal, debug, info, error) ", err)
				break
			}
		case 'l':
			c.ARPPrintTable()
		case 'f':
			entry := getMAC(c, text)
			if entry != nil {
				c.ARPForceIPChange(entry.MAC, entry.IP)
			}
		case 's':
			entry := getMAC(c, text)
			if entry != nil {
				c.StopIPChange(entry.MAC)
			}
		}
	}
}

func NICGetInformation(nic string) (ip net.IP, mac net.HardwareAddr, err error) {

	ifi, err := net.InterfaceByName(nic)
	if err != nil {
		log.WithFields(log.Fields{"nic": nic}).Errorf("NIC cannot open nic %s error %s ", nic, err)
		return ip, mac, err
	}

	mac = ifi.HardwareAddr

	addrs, err := ifi.Addrs()
	if err != nil {
		log.WithFields(log.Fields{"nic": nic}).Errorf("NIC cannot get addresses nic %s error %s ", nic, err)
		return ip, mac, err
	}

	for i := range addrs {
		tmp, _, _ := net.ParseCIDR(addrs[i].String())
		ip = tmp.To4()
		if !ip.Equal(net.IPv4zero) {
			break
		}
	}

	if ip == nil || ip.Equal(net.IPv4zero) {
		err = fmt.Errorf("NIC cannot find IPv4 address list - is %s up?", nic)
		log.Error(err)
		return ip, mac, err
	}

	log.WithFields(log.Fields{"nic": nic, "ip": ip, "mac": mac}).Info("NIC successfull acquired host nic information")
	return ip, mac, err
}

func SetLogLevel(level string) (err error) {

	log.SetLevel(log.InfoLevel)

	if level != "" {
		l, err := log.ParseLevel(level)
		if err == nil {
			log.SetLevel(l)
		} else {
			log.Warn("Invalid log level: ", level)
		}
	}
	return err
}
