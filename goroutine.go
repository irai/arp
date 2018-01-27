package arp

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"time"
)

type GoroutinePool struct {
	// goroutines should wait on StopChannel with "<- StopChannel"
	StopChannel    chan struct{}
	stoppedChannel chan int
	n              int
	Stopping       bool
	name           string
}

func (h *GoroutinePool) Init(name string) {
	h.name = name
	h.Stopping = false
	h.StopChannel = make(chan struct{})
	h.stoppedChannel = make(chan int)
}

func (h *GoroutinePool) Begin() *GoroutinePool {
	h.n++
	return h
}

func (h *GoroutinePool) End() {
	h.stoppedChannel <- 1
}

func (h *GoroutinePool) Stop() error {
	// closing stopChannel will cause all waiting goroutines to exit
	h.Stopping = true
	close(h.StopChannel)

	for {
		select {
		// wait for n goroutines to finish
		case <-h.stoppedChannel:
			h.n--
			log.Infof("%s goroutine stopped - remaining %d", h.name, h.n)
			if h.n <= 0 {
				return nil
			}
		case <-time.After(5 * time.Second):
			log.Error("ARP stop timed out")
			return errors.New("timeout")
		}
	}
	return nil
}
