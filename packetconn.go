package arp

import (
	"fmt"
	"net"
	"sync"
	"time"

	marp "github.com/mdlayher/arp"
)

// bufferReadFromPacketConn is a net.PacketConn which copies bytes from its
// embedded buffer into b when when its ReadFrom method is called.
type bufferedPacketConn struct {
	channel chan []byte
	closed  bool
}

// NewTestHandler allow you to pass a PacketConn. Useful for testing
// if p is nil, auto create a bufferedPacketConn
func NewTestHandler(config Config, p net.PacketConn) (c *Handler, conn *marp.Client, err error) {
	c = newHandler(config)
	c.table = newARPTable() // we want an empty table for testing
	ifi, err := net.InterfaceByName(config.NIC)
	if err != nil {
		return nil, nil, fmt.Errorf("InterfaceByName error: %w", err)
	}
	if p == nil {
		p = &bufferedPacketConn{channel: make(chan []byte, 32)}
	}
	if c.client, err = marp.New(ifi, p); err != nil {
		return nil, nil, err
	}
	return c, c.client, nil
}

var channelMutex sync.Mutex // avoid race in Close()

func (p *bufferedPacketConn) Close() error {
	channelMutex.Lock()
	defer channelMutex.Unlock()

	if !p.closed {
		close(p.channel)
		p.closed = true
	}
	return nil
}
func (p *bufferedPacketConn) LocalAddr() net.Addr                { return nil }
func (p *bufferedPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *bufferedPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *bufferedPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (p *bufferedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if p.closed {
		return 0, nil, fmt.Errorf("closed")
	}
	data := <-p.channel
	n := copy(b, data)
	return n, nil, nil
}

func (p *bufferedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.closed {
		return 0, fmt.Errorf("closed")
	}
	p.channel <- b
	return len(b), nil
}
