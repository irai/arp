package arp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

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

func Test_ServeRequests(t *testing.T) {
	//Debug = true
	// log.SetLevel(log.DebugLevel)
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
		{"request5-2", newPacket(marp.OperationRequest, mac5, ip2, zeroMAC, routerIP), nil, 4, 2},
		{"request5-3", newPacket(marp.OperationRequest, mac5, ip3, zeroMAC, routerIP), nil, 4, 3},
		{"announce5-4", newPacket(marp.OperationRequest, mac5, ip4, zeroMAC, ip4), nil, 4, 4},
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

func Test_ServeReplies(t *testing.T) {
	// Debug = true
	// log.SetLevel(log.DebugLevel)
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
		{"replyHost", newPacket(marp.OperationReply, hostMAC, hostIP, mac2, ip2), nil, 0, 0},
		{"replyRouter", newPacket(marp.OperationReply, routerMAC, routerIP, mac2, ip2), nil, 0, 0},
		{"locallink", newPacket(marp.OperationReply, mac2, net.IPv4(169, 254, 0, 10), zeroMAC, net.IPv4(169, 254, 0, 10)), nil, 0, 0}, // link local 169.254.x.x
		{"reply2", newPacket(marp.OperationReply, mac2, ip2, routerMAC, routerIP), nil, 1, 1},
		{"reply2-2", newPacket(marp.OperationReply, mac2, ip2, hostMAC, hostIP), nil, 1, 1},
		{"request2", newPacket(marp.OperationRequest, mac2, ip2, zeroMAC, ip3), nil, 1, 1}, // add a request in the middle
		{"reply2-3", newPacket(marp.OperationReply, mac2, ip2, hostMAC, hostIP), nil, 1, 1},
		{"reply2-4", newPacket(marp.OperationReply, mac2, ip3, hostMAC, hostIP), nil, 1, 2},
		{"request3", newPacket(marp.OperationRequest, mac3, ip3, zeroMAC, routerIP), nil, 2, 1},
		{"reply3-1", newPacket(marp.OperationReply, mac3, ip4, hostMAC, hostIP), nil, 2, 2},
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
func Test_CaptureSameIP(t *testing.T) {
	// Debug = true
	// log.SetLevel(log.DebugLevel)
	h := testHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		h.ListenAndServe(ctx)
		wg.Done()
	}()

	e, _ := h.table.upsert(StateNormal, mac2, ip2)
	e.Online = true
	time.Sleep(time.Millisecond * 20) // time for ListenAndServe to start
	h.ForceIPChange(mac2)

	tests := []struct {
		name      string
		packet    *marp.Packet
		wantErr   error
		wantLen   int
		wantIPs   int
		wantState arpState
	}{
		{"request5-1", newPacket(marp.OperationRequest, mac5, ip5, zeroMAC, hostIP), nil, 3, 1, StateNormal},
		{"reply2-1", newPacket(marp.OperationReply, mac2, ip2, zeroMAC, hostIP), nil, 3, 1, StateHunt},
		{"reply2-2", newPacket(marp.OperationReply, mac2, ip2, zeroMAC, hostIP), nil, 3, 1, StateHunt},
		{"reply2-3", newPacket(marp.OperationReply, mac2, ip2, hostMAC, hostIP), nil, 3, 1, StateHunt},
		{"reply2-4", newPacket(marp.OperationReply, mac2, ip2, routerMAC, routerIP), nil, 3, 1, StateHunt},
		{"reply2-4", newPacket(marp.OperationReply, mac2, ip2, mac3, ip3), nil, 3, 1, StateHunt},
		{"request2-1", newPacket(marp.OperationRequest, mac2, ip2, zeroMAC, routerIP), nil, 3, 1, StateHunt},
		{"request2-2", newPacket(marp.OperationRequest, mac2, ip2, zeroMAC, hostIP), nil, 3, 1, StateHunt},
		{"request2-4", newPacket(marp.OperationRequest, mac2, ip2, mac3, ip3), nil, 3, 1, StateHunt},
		{"request3-1", newPacket(marp.OperationRequest, mac2, ip3, zeroMAC, hostIP), nil, 3, 1, StateNormal},
		{"request4-1", newPacket(marp.OperationRequest, mac2, ip4, zeroMAC, hostIP), nil, 3, 2, StateNormal},
		{"request3-2", newPacket(marp.OperationRequest, mac2, ip2, zeroMAC, ip2), nil, 3, 2, StateNormal}, // announce old IP
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := h.client.WriteTo(tt.packet, nil); err != tt.wantErr {
				t.Errorf("Test_Capture:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)
			if len(h.table.macTable) != tt.wantLen {
				t.Errorf("Test_Capture:%s table len = %v, wantLen %v", tt.name, len(h.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := h.table.findByMAC(tt.packet.SenderHardwareAddr)
				if e == nil || len(e.IPs) != tt.wantIPs {
					t.Errorf("Test_Capture:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
				if e.State != tt.wantState {
					t.Errorf("Test_Capture:%s entry state=%s, wantState %v", tt.name, e.State, tt.wantState)

				}
			}
		})
	}
	cancel()
	wg.Wait()
}
