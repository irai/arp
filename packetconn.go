package arp

import (
	"net"
	"time"
)

// bufferReadFromPacketConn is a net.PacketConn which copies bytes from its
// embedded buffer into b when when its ReadFrom method is called.
type bufferedPacketConn struct {
	channel chan []byte
}

func newBufferedPacketConn() *bufferedPacketConn {
	return &bufferedPacketConn{channel: make(chan []byte, 32)}
}

func (p *bufferedPacketConn) Close() error                       { close(p.channel); return nil }
func (p *bufferedPacketConn) LocalAddr() net.Addr                { return nil }
func (p *bufferedPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *bufferedPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *bufferedPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (p *bufferedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	data := <-p.channel
	n := copy(b, data)
	return n, nil, nil
}

func (p *bufferedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.channel <- b
	return len(b), nil
}
