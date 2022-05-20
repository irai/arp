# arp golang

The package implements a user level arp table management in golang that
monitor the local network for ARP changes and provide notifications
when a MAC switch between online and offline.

**NOTE: A new package [packet](https://github.com/irai/packet) has better arp spoofing support**  
This package is functional and useful for experimentation but all efforts going forward 
focus on [packet](https://github.com/irai/packet) which addresses many issues
and in addition to arp spoofing it also support general packet mangling and dhcp4 and icmp6 spoofing.


## Force IP address change (IP spoofing)
The most useful function is to force an IP address change by claiming
the IP of a target MAC. It achieves this by persistently claiming the 
IP address using ARP request/reply and activelly hunting the target MAC
until it gives up its IP. This is very effective against mobile devices 
using DHCP however it does not work when client is using static address. 


The package uses low level arp packets to enable:
* network discovery by polling 254 addresses 
* notification when a MAC switch between online and offline
* forced IP address change 

See the arplistener example for how to use it.

Limitations
-----------
* Tested on linux (Raspberry PI arm). Should work on Windows with tiny changes.
* IPv4 only


Getting started
---------------
```bash
	$ go get github.com/irai/arp
	$ cd $GOPATH/src/github.com/irai/arp/arplistener
	$ go install
	$ sudo $GOPATH/bin/arplistener -i eth0
```

Create your own listener in a goroutine
---------------------------------------
Simply create a new handler and run ListenAndServe in a goroutine. The goroutine will
listen for ARP changes and generate a notification each time a mac changes between online/offline.

```golang
	HomeRouterIP := net.ParseIP("192.168.0.1").To4()
	HomeLAN := net.IPNet{IP: net.ParseIP("192.168.0.0").To4(), Mask: net.CIDRMask(25, 32)}
	NIC := "eth0"
	HostMAC, _ := net.ParseMAC("xx:xx:xx:xx:xx:xx")
	HostIP := net.ParseIP("192.168.1.2").To4()

	c, err := arp.New(arp.Config{
		NIC:                     NIC,
		HostMAC:                 HostMAC,
		HostIP:                  HostIP,
		RouterIP:                HomeRouterIP,
		HomeLAN:                 HomeLAN,
		ProbeInterval:           time.Minute,
		FullNetworkScanInterval: 0,
	})
	if err != nil {
		log.Fatal("error ", err)
	}
	defer c.Close()

	go c.ListenAndServe(context.Background())

	c.printTable()
```

Listen to changes to mac table

New a message broker function
```golang
func arpNotification(arpChannel chan arp.MACEntry) {
	for {
		select {
		case MACEntry := <-arpChannel:
			log.Warnf("notification got ARP MACEntry for %s", MACEntry.MAC)

		}
	}
}
```

```golang
arpChannel := make(chan arp.MACEntry, 16)
c.AddNotificationChannel(arpChannel)

go arpNotification(arpChannel)
```


To force an IP change simply invoke ForceIPChange with the current mac and ip value.
```golang
MACEntry := c.findByMAC("xx:xx:xx:xx:xx:xx")
c.ForceIPChange(MACEntry.MAC, MACEntry.IP)
```
