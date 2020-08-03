package arp

import (
	"bytes"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func Test_bufferedPacketConn_ReadFrom(t *testing.T) {
	c := &bufferedPacketConn{channel: make(chan []byte, 32)}

	sent := []byte("test")
	sent2 := []byte("test2")
	c.WriteTo(sent, nil)

	recvd := make([]byte, 256)
	c.ReadFrom(recvd)
	if bytes.Equal(sent, recvd) {
		log.Error("error in size ", sent, recvd)
	}

	go func() {
		time.Sleep(time.Second * 10)
		c.WriteTo(sent2, nil)
	}()

	c.ReadFrom(recvd)
	if bytes.Equal(sent2, recvd) {
		log.Error("error in size ", sent2, recvd)
	}

}
