package arp

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// pollingLoop detect new IPs on the network
// Send ARP request to all 255 IP addresses first time then send ARP request every so many minutes.
func (c *Handler) scanLoop(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval).C
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker:
			if err := c.ScanNetwork(c.config.HomeLAN); err != nil {
				return fmt.Errorf("scanLoop goroutine failed: %w", err)
			}
		}
	}
}

// Probe known macs more often in case they left the network.
func (c *Handler) probeOnlineLoop(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(time.Second * 30).C
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker:
			refreshCutoff := time.Now().Add(interval * -1)
			c.RLock()

			for _, v := range c.table.ipTable {
				if v.LastUpdated.Before(refreshCutoff) {
					// Ignore empty entries and link local
					// if e.IP.IsLinkLocalUnicast() {
					// continue
					// }
					if LogAll {
						log.WithFields(log.Fields{"mac": v.MACEntry.MAC, "ip": v}).Debug("Is device online? requesting...")
					}
					if err := c.request(c.config.HostMAC, c.config.HostIP, v.MACEntry.MAC, v.IP); err != nil {
						log.WithFields(log.Fields{"mac": v.MACEntry.MAC, "ip": v.IP}).Error("Error ARP request: ", err)
					}
				}
			}
			c.RUnlock()
		}
	}
}

func (c *Handler) purgeLoop(ctx context.Context, interval time.Duration) error {

	ticker := time.NewTicker(interval).C
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker:

			now := time.Now()
			offlineCutoff := now.Add(interval * -1)        // Mark offline entries last updated before this time
			deleteCutoff := now.Add(time.Minute * 60 * -1) // Delete entries that have not responded in last hour
			macs := make([]net.HardwareAddr, 16)

			c.Lock()
			for _, e := range c.table.ipTable {

				// Delete from ARP table if the device was not seen for the last hour
				if e.MACEntry.LastUpdated.Before(deleteCutoff) {
					macs = append(macs, e.MACEntry.MAC)
					continue
				}

				// Set offline if no updates since the offline deadline
				if e.MACEntry.Online && e.LastUpdated.Before(offlineCutoff) {
					log.WithFields(log.Fields{"mac": e.MACEntry.MAC, "ips": e.MACEntry.IPs}).Info("ARP device is offline")

					e.MACEntry.Online = false
					e.MACEntry.State = StateNormal // Stop hunt if in progress

					// Notify upstream the device changed to offline
					if c.notification != nil {
						c.notification <- *e.MACEntry
					}
				}
			}

			// delete after loop because this will change the ipTable map
			for i := range macs {
				c.table.delete(macs[i])
			}
			c.Unlock()
		}
	}
}

func (c *Handler) ScanNetwork(lan net.IPNet) error {

	// Copy underneath array so we can modify value.
	ip := lan.IP

	if LogAll {
		log.Debugf("ARP Discovering IP - sending 254 ARP requests - lan %v", lan)
	}
	for host := 1; host < 255; host++ {
		ip[3] = byte(host)

		// Skip entries that are online; these will be checked somewhere else
		//
		if MACEntry := c.table.findByIP(ip); MACEntry != nil && MACEntry.Online {
			if LogAll {
				log.WithFields(log.Fields{"mac": MACEntry.MAC, "ip": MACEntry.IP}).Debug("ARP skip request for online device")
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
