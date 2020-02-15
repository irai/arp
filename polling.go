package arp

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// pollingLoop detect new MACs and also when existing MACs are no longer online.
// Send ARP request to all 255 IP addresses first time then send ARP request every so many minutes.
// Probe known macs more often in case they left the network.
//
// checkNewDevicesInterval is the the duration between full scans
func (c *Handler) pollingLoop(checkNewDevicesInterval time.Duration) (err error) {
	// Goroutine pool
	h := c.goroutinePool.Begin("ARP pollingLoop")
	defer h.End()

	if checkNewDevicesInterval > 0 {
		c.scanNetwork()
	} else {
		checkNewDevicesInterval = time.Minute * 60 * 24 * 365 * 20 // will never expire
	}

	// Retrieve router mac if available
	time.Sleep(time.Millisecond * 300)
	if router := c.FindIP(c.config.RouterIP); router != nil {
		c.config.RouterMAC = router.MAC
	}

	// Ticker used to perform full scan
	checkNewDevices := time.NewTicker(checkNewDevicesInterval).C
	checkDeviceIsActive := time.NewTicker(time.Second * 30).C // Check every 30 seconds
	for {
		// timer for probing known macs
		select {
		case <-checkNewDevices:
			c.scanNetwork()
			// update router mac in case it has changed
			if router := c.FindIP(c.config.RouterIP); router != nil {
				c.config.RouterMAC = router.MAC
			}

		case <-c.goroutinePool.StopChannel:
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
	refreshDeadline := now.Add(time.Second * 90 * -1) // Refresh entries last updated before this time
	offlineDeadline := now.Add(time.Minute * 4 * -1)  // Mark offline entries last updated before this time
	deleteDeadline := now.Add(time.Minute * 60 * -1)  // Delete entries that have not responded in last hour

	if LogAll {
		log.Debug("ARP scan online devices")
	}
	for i, e := range table {

		// Ignore empty entries
		if e == nil {
			continue
		}

		c.mutex.Lock()
		local := &Entry{}
		*local = *e // local copy to avoid race
		c.mutex.Unlock()

		// Don't probe virtual entries - these are always online until deletion
		if local.State == StateVirtualHost {
			continue
		}

		// Delete from ARP table if the device was not seen for the last hour
		if local.LastUpdate.Before(deleteDeadline) {
			if local.Online == true {
				log.Warn("ARP device is not offline during delete", local.MAC)
			}
			if LogAll {
				log.WithFields(log.Fields{"mac": local.MAC, "ip": local.IP}).
					Infof("ARP delete entry online %5v state %10s", local.Online, local.State)
			}

			c.mutex.Lock()
			table[i] = nil // use the index to set the array to nil
			c.mutex.Unlock()
			continue
		}

		// probe only in these two cases:
		//   1) device is online and have not received an update recently; or
		//   2) device is offline and no more than one hour has passed.
		//
		if local.LastUpdate.Before(refreshDeadline) {
			if LogAll {
				log.WithFields(log.Fields{"mac": local.MAC, "ip": local.IP}).Debug("Is device online? requesting...")
			}
			if err := c.request(c.config.HostMAC, c.config.HostIP, local.MAC, local.IP); err != nil {
				log.WithFields(log.Fields{"mac": local.MAC, "ip": local.IP}).Error("Error ARP request: ", err)
			}

			// Give it a chance to update
			time.Sleep(time.Millisecond * 15)

			// Set to offline if no updates since the offline deadline
			if local.Online && local.LastUpdate.Before(offlineDeadline) {
				log.WithFields(log.Fields{"mac": local.MAC, "ip": local.IP}).Info("ARP device is offline")

				c.mutex.Lock()
				table[i].Online = false
				table[i].State = StateNormal // Stop hunt if in progress
				c.mutex.Unlock()

				// Notify upstream the device changed to offline
				if c.notification != nil {
					c.notification <- *table[i]
				}
			}
		} else {
			// Notify upstream the device is still online
			// This will send an update every 30 seconds aprox
			// Update last seen upstream
			if table[i].Online && c.notification != nil {
				c.notification <- *table[i]
			}
		}
	}
}

func (c *Handler) scanNetwork() error {

	// Copy underneath array so we can modify value.
	ip := dupIP(c.config.HomeLAN.IP)

	if LogAll {
		log.Debug("ARP Discovering IP - sending 254 ARP requests")
	}
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// Skip entries that are online; these will be checked somewhere else
		//
		if entry := c.FindIP(ip); entry != nil && entry.Online {
			if LogAll {
				log.WithFields(log.Fields{"mac": entry.MAC, "ip": entry.IP}).Debug("ARP skip request for online device")
			}
			continue
		}

		err := c.request(c.config.HostMAC, c.config.HostIP, EthernetBroadcast, ip)
		if c.goroutinePool.Stopping() {
			return nil
		}
		if err != nil {
			log.Error("ARP request error ", err)
			if err1, ok := err.(net.Error); ok && err1.Temporary() {
				if LogAll {
					log.Debug("ARP error in read socket is temporary - retry", err1)
				}
				time.Sleep(time.Millisecond * 100) // Wait before retrying
				continue
			}

			return err
		}
		time.Sleep(time.Millisecond * 25)
	}

	return nil
}
