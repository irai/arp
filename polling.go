package arp

import (
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

const (
	confirmIsActiveFrequency = time.Second * 120
)

// pollingLoop detect new MACs and also when existing MACs are no longer online.
// Send ARP request to all 255 IP addresses first time then send ARP request every so many minutes.
// Probe known macs more often in case they left the network.
//
// checkNewDevicesInterval is the the duration between full scans
//
func (c *ARPClient) pollingLoop(checkNewDevicesInterval time.Duration) (err error) {
	// Goroutine pool
	h := c.workers.Begin("scanloop", false)
	defer h.End()

	c.scanNetwork()

	// Ticker used to perform full scan
	checkNewDevices := time.NewTicker(checkNewDevicesInterval).C
	checkDeviceIsActive := time.NewTicker(confirmIsActiveFrequency).C
	for {
		// timer for probing known macs
		select {
		case <-checkNewDevices:
			c.scanNetwork()

		case <-c.workers.StopChannel:
			log.Info("ARP stopping probeLoop")
			return nil

		case <-checkDeviceIsActive:
			c.confirmIsActive()
		}
	}
	return nil
}

func (c *ARPClient) confirmIsActive() {

	c.mutex.Lock()
	table := c.table[:]
	c.mutex.Unlock()

	now := time.Now()
	refreshDeadline := now.Add(confirmIsActiveFrequency * -1)                   // Refresh entries last updated before this time
	offlineDeadline := now.Add((confirmIsActiveFrequency*2 + time.Minute) * -1) // Mark offline entries last updated before this time
	deleteDeadline := now.Add(time.Minute * 60 * -1)                            // Delete entries that have not responded in last hour

	log.Info("ARP refresh online devices")
	for i := range table {

		// Ignore virtual entries - these are always online
		if table[i].State == ARPStateVirtualHost ||
			table[i].State == ARPStateDeleted {
			continue
		}

		// Delete from ARP table if the device was not seen for the last hour
		if table[i].LastUpdate.Before(deleteDeadline) {
			if table[i].Online == true {
				log.Error("ARP device is not offline during delete")
			}
			c.delete(&table[i])
			continue
		}

		// probe only in these two cases:
		//   1) device is online and have not received an update recently; or
		//   2) device is offline and no more than one hour has passed.
		//
		// if (table[i].Online == true && table[i].LastUpdate.Before(refreshDeadline)) ||
		// (table[i].Online == false && table[i].LastUpdate.After(deleteDeadline)) {

		var ip net.IP

		if table[i].LastUpdate.Before(refreshDeadline) {
			switch table[i].State {
			case ARPStateHunt:
				ip = table[i].PreviousIP
				// err = c.probeUnicast(table[i].MAC, table[i].PreviousIP) // not all devices implement ACD
				// err = c.Request(c.config.HostMAC, c.config.HostIP, table[i].MAC, table[i].PreviousIP)
			default:
				// err = c.probeUnicast(table[i].MAC, table[i].IP)
				// err = c.Request(c.config.HostMAC, c.config.HostIP, table[i].MAC, table[i].IP)
				ip = table[i].IP
			}

			if err := c.Request(c.config.HostMAC, c.config.HostIP, table[i].MAC, ip); err != nil {
				log.WithFields(log.Fields{"clientmac": table[i].MAC, "clientip": ip}).Error("Error ARP request: ", err)
			}

			// Give it a chance to update
			time.Sleep(time.Millisecond * 15)

			if table[i].LastUpdate.Before(offlineDeadline) {
				if table[i].Online == true {
					log.WithFields(log.Fields{"clientmac": table[i].MAC, "clientip": table[i].IP}).Warn("ARP device is offline")

					table[i].Online = false
					table[i].LastUpdate = now

					// Notify upstream the device changed to offline
					if c.notification != nil {
						c.notification <- table[i]
					}
				}
			}
		}
	}
}

func (c *ARPClient) scanNetwork() error {

	// Copy underneath array so we can modify value.
	ip := net.ParseIP(c.config.HomeLAN.IP.String()).To4()

	log.Info("ARP Discovering IP - sending 254 ARP requests")
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// Skip entries that are online; these will be checked somewhere else
		//
		if entry := c.ARPFindIP(ip); entry != nil && entry.Online {
			log.WithFields(log.Fields{"clientmac": entry.MAC, "clientip": entry.IP}).Debug("ARP skip request for online device")
			continue
		}

		err := c.request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, ip)
		if err != nil {
			log.Error("ARP request error ", err)
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				log.Info("ARP error in read socket is temporary - retry", err1)
				time.Sleep(time.Millisecond * 100) // Wait before retrying
				continue
			}

			return err
		}
		time.Sleep(time.Millisecond * 25)
	}

	return nil
}
