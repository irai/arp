package arp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	marp "github.com/mdlayher/arp"
)

var packets []marp.Packet = []marp.Packet{
	{
		HardwareType:       1,
		ProtocolType:       uint16(2048),
		HardwareAddrLength: 6,
		IPLength:           4,
		Operation:          marp.OperationRequest,
		SenderHardwareAddr: mac2,
		SenderIP:           ip2,
		TargetHardwareAddr: zeroMAC,
		TargetIP:           ip3,
	},
}

func newPacket(op marp.Operation, sMAC net.HardwareAddr, sIP net.IP, tMAC net.HardwareAddr, tIP net.IP) *marp.Packet {
	p, _ := marp.NewPacket(op, sMAC, sIP, tMAC, tIP)
	return p
}

func Test_Requests(t *testing.T) {
	Debug = true
	log.SetLevel(log.DebugLevel)
	log.Print("asdfasdf")
	h := testHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		h.ListenAndServe(ctx)
		wg.Done()
	}()

	tests := []struct {
		name    string
		packet  *marp.Packet
		wantErr error
		wantLen int
		wantIPs int
	}{
		{"request2", newPacket(marp.OperationRequest, mac2, ip2, zeroMAC, ip3), nil, 1, 1},
		{"request2-dup2", newPacket(marp.OperationRequest, mac2, ip2, zeroMAC, ip3), nil, 1, 1},
		{"request2-dup3", newPacket(marp.OperationRequest, mac2, ip2, zeroMAC, ip3), nil, 1, 1},
		{"request2-dup4", newPacket(marp.OperationRequest, mac2, ip2, zeroMAC, ip3), nil, 1, 1},
		{"request3", newPacket(marp.OperationRequest, mac3, ip3, zeroMAC, routerIP), nil, 2, 1},
		{"announce4", newPacket(marp.OperationRequest, mac4, ip4, zeroMAC, ip4), nil, 3, 1},
		{"router", newPacket(marp.OperationRequest, zeroMAC, routerIP, zeroMAC, ip3), nil, 3, 0},
		{"announceRouter", newPacket(marp.OperationRequest, zeroMAC, routerIP, zeroMAC, routerIP), nil, 3, 0},
		{"announceHost", newPacket(marp.OperationRequest, hostMAC, hostIP, zeroMAC, hostIP), nil, 3, 0},
		{"host", newPacket(marp.OperationRequest, hostMAC, hostIP, zeroMAC, ip4), nil, 3, 0},
		{"announce5", newPacket(marp.OperationRequest, mac5, ip5, zeroMAC, ip5), nil, 4, 1},
		{"request5", newPacket(marp.OperationRequest, mac5, ip5, zeroMAC, routerIP), nil, 4, 1},
		{"probe", newPacket(marp.OperationRequest, mac2, net.IPv4zero, zeroMAC, ip4), nil, 4, 0},                                        // probe has sIP zero
		{"locallink", newPacket(marp.OperationRequest, mac2, net.IPv4(169, 254, 0, 10), zeroMAC, net.IPv4(169, 254, 0, 10)), nil, 4, 0}, // link local 169.254.x.x
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := h.client.WriteTo(tt.packet, nil); err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)
			if len(h.table.macTable) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(h.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := h.table.findByMAC(tt.packet.SenderHardwareAddr)
				if e == nil || len(e.IPs) != tt.wantIPs {
					t.Errorf("Test_Requests:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
			}
		})
	}
	cancel()
	wg.Wait()

}
