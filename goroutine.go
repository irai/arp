package arp

import (
	"errors"
	"sync"
	"sync/atomic"

	"time"

	log "github.com/sirupsen/logrus"
)

type goroutinePool struct {
	// goroutines should wait on StopChannel with "<- StopChannel"
	StopChannel    chan struct{}
	stoppedChannel chan *goroutine
	n              int32 // atomic value
	stopping       int32 // atomic value
	name           string
	mutex          sync.Mutex
}

type goroutine struct {
	name string
	pool *goroutinePool
}

// GoroutinePool tracks background goroutines and enable termination.
//
// Usage:
//
// go {
//     h := GoroutinePool.Begin("name")
//     defer h.End()}
//
//     for {
//      select {
//      case <-GoroutinePool.StopChannel:
//        return
//      }
//     }
//  }()
//
// GoroutinePool.Stop()
var GoroutinePool = &goroutinePool{name: "default", stopping: 0, StopChannel: make(chan struct{}), stoppedChannel: make(chan *goroutine)}

// new create a new go routine pool
// do want to export this yet
func (h *goroutinePool) new(name string) (ret *goroutinePool) {
	ret = &goroutinePool{}
	ret.name = name
	ret.stopping = 0
	ret.StopChannel = make(chan struct{})
	ret.stoppedChannel = make(chan *goroutine)

	return ret
}

// Begin records the begining of a new goroutine in the pool.
// name is the name printed on exit
// server - set to true if this is a background goroutine that should never end
func (h *goroutinePool) Begin(name string) *goroutine {
	g := goroutine{name: name, pool: h}
	atomic.AddInt32(&h.n, 1)
	if LogAll {
		log.Debugf("%s goroutine started", g.name)
	}
	return &g
}

func (h *goroutinePool) Stopping() bool {
	if atomic.LoadInt32(&h.stopping) != 0 {
		return true
	}
	return false
}

func (g *goroutine) End() {
	atomic.AddInt32(&g.pool.n, -1)
	stopping := atomic.LoadInt32(&g.pool.stopping)
	if LogAll {
		log.Debugf("%s goroutine finished - remaining %d", g.name, atomic.LoadInt32(&g.pool.n))
	}
	if stopping != 0 {
		g.pool.stoppedChannel <- g
	}
}

// Stop send a channel msg to stop running goroutines
func (h *goroutinePool) Stop() error {
	// closing stopChannel will cause all waiting goroutines to exit
	atomic.StoreInt32(&h.stopping, 1)
	close(h.StopChannel)

	for {
		n := atomic.LoadInt32(&h.n)
		if n <= 0 {
			return nil
		}

		select {
		// wait for n goroutines to finish
		case <-h.stoppedChannel:

		case <-time.After(5 * time.Second):
			log.Errorf("%s stop timed out", h.name)
			return errors.New("timeout")
		}
	}
}

// Stopping is true if the pool is attempting to stop all goroutines.
func (g *goroutine) Stopping() bool {
	if stopping := atomic.LoadInt32(&g.pool.stopping); stopping != 0 {
		return true
	}
	return false
}
