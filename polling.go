package arp

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	confirmIsActiveFrequency = time.Second * 120
)

// pollingLoop detect new MACs and also when existing MACs are no longer online.
// Send ARP request to all 255 IP addresses first time then send ARP request every so many minutes.
// Probe known macs more often in case they left the network.
//
// checkNewDevicesInterval is the the duration between full scans
func (c *Handler) pollingLoop(checkNewDevicesInterval time.Duration) (err error) {
	// Goroutine pool
	h := c.workers.Begin("pollingLoop")
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
			return nil

		case <-checkDeviceIsActive:
			c.confirmIsActive()
		}
	}
}

func (c *Handler) confirmIsActive() {

	c.mutex.Lock()
	table := c.table // fix the table slice; c.table may change
	c.mutex.Unlock()

	now := time.Now()
	refreshDeadline := now.Add(confirmIsActiveFrequency * -1)                   // Refresh entries last updated before this time
	offlineDeadline := now.Add((confirmIsActiveFrequency*2 + time.Minute) * -1) // Mark offline entries last updated before this time
	deleteDeadline := now.Add(time.Minute * 60 * -1)                            // Delete entries that have not responded in last hour

	log.Info("ARP refresh online devices")
	for i, entry := range table {

		// Ignore empty entries
		if entry == nil {
			continue
		}

		// Delete from ARP table if the device was not seen for the last hour
		if entry.LastUpdate.Before(deleteDeadline) {
			if entry.Online == true {
				log.Warn("ARP device is not offline during delete", entry.MAC)
			}
			log.WithFields(log.Fields{"clientmac": entry.MAC, "clientip": entry.IP}).
				Infof("ARP delete entry online %5v state %10s", entry.Online, entry.State)

			c.mutex.Lock()
			table[i] = nil // use the index to set the array to nil
			c.mutex.Unlock()
			continue
		}

		// Don't probe virtual entries - these are always online until deletion
		if entry.State == StateVirtualHost {
			continue
		}

		// probe only in these two cases:
		//   1) device is online and have not received an update recently; or
		//   2) device is offline and no more than one hour has passed.
		//
		if entry.LastUpdate.Before(refreshDeadline) {
			if err := c.request(c.config.HostMAC, c.config.HostIP, entry.MAC, entry.IP); err != nil {
				log.WithFields(log.Fields{"clientmac": entry.MAC, "clientip": entry.IP}).Error("Error ARP request: ", err)
			}

			// Give it a chance to update
			time.Sleep(time.Millisecond * 15)

			if entry.LastUpdate.Before(offlineDeadline) {
				if entry.Online == true {
					log.WithFields(log.Fields{"clientmac": entry.MAC, "clientip": entry.IP}).Warn("ARP device is offline")

					entry.Online = false
					entry.LastUpdate = now

					// Notify upstream the device changed to offline
					if c.notification != nil {
						c.notification <- *entry
					}
				}
			}
		}
	}
}

func (c *Handler) scanNetwork() error {

	// Copy underneath array so we can modify value.
	ip := dupIP(c.config.HomeLAN.IP)

	log.Info("ARP Discovering IP - sending 254 ARP requests")
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// Skip entries that are online; these will be checked somewhere else
		//
		if entry := c.FindIP(ip); entry != nil && entry.Online {
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
