package arp

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"time"
)

// GoroutinePool tracks background goroutines and enable termination.
//
// Usage:
// workers base.GoroutinePool
// workers.init("name")
//
// go {
//     h := c.workers.Begin()
//     defer h.End()}
//
//     for {
//      select {
//      case <-workers.StopChannel:
//        return
//      }
//     }
//  }()
//
// workers.Stop()

type GoroutinePool struct {
	// goroutines should wait on StopChannel with "<- StopChannel"
	StopChannel    chan struct{}
	stoppedChannel chan *goroutine
	n              int
	Stopping       bool
	name           string
}

type goroutine struct {
	name   string
	server bool
	pool   *GoroutinePool
}

func (h *GoroutinePool) Init(name string) {
	h.name = name
	h.Stopping = false
	h.StopChannel = make(chan struct{})
	h.stoppedChannel = make(chan *goroutine)
}

// Begin records the begining of a new goroutine in the pool.
// name is the name printed on exit
// server - set to true if this is a background goroutine that should never end
func (h *GoroutinePool) Begin(name string, server bool) *goroutine {
	g := goroutine{name: name, server: server, pool: h}
	h.n++
	log.Infof("%s %s goroutine started", g.pool.name, g.name)
	return &g
}

func (g *goroutine) End() {
	if g.pool.Stopping || g.server == false {
		log.Infof("%s %s goroutine completed", g.pool.name, g.name)
	} else {
		log.Fatalf("%s %s goroutine terminated unexpectedly ", g.pool.name, g.name)
	}
	g.pool.stoppedChannel <- g
}

func (h *GoroutinePool) Stop() error {
	// closing stopChannel will cause all waiting goroutines to exit
	h.Stopping = true
	close(h.StopChannel)

	for {
		select {
		// wait for n goroutines to finish
		case g := <-h.stoppedChannel:
			h.n--
			log.Infof("%s %s stopped - remaining %d", h.name, g.name, h.n)
			if h.n <= 0 {
				return nil
			}
		case <-time.After(5 * time.Second):
			log.Errorf("%s stop timed out", h.name)
			return errors.New("timeout")
		}
	}
}
