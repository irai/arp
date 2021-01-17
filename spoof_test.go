package arp

import (
	"context"
	"sync"
	"testing"
	"time"

	marp "github.com/mdlayher/arp"
)

func TestHandler_ForceIPChange(t *testing.T) {
	//Debug = true
	// log.SetLevel(log.DebugLevel)
	h, conn := testHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		h.ListenAndServe(ctx)
		wg.Done()
	}()

	time.Sleep(time.Millisecond * 20) // time for ListenAndServe to start
	e2, _ := h.table.upsert(StateNormal, mac2, ip2)
	e2.Online = true
	h.table.updateIP(e2, ip3)
	h.table.updateIP(e2, ip4)
	h.ForceIPChange(e2.MAC, true)

	if e := h.table.findByMAC(mac2); e == nil || e.State != StateHunt || !e.Online {
		t.Fatalf("Test_ForceIPChange entry2 state=%s, online=%v", e.State, e.Online)
	}

	tests := []struct {
		name    string
		packet  *marp.Packet
		wantErr error
		wantLen int
		wantIPs int
	}{
		{"request3", newPacket(marp.OperationRequest, mac2, ip4, zeroMAC, ip4), nil, 4, 3},
		{"request4", newPacket(marp.OperationRequest, mac2, ip4, zeroMAC, ip4), nil, 4, 3},
		{"request5", newPacket(marp.OperationRequest, mac2, ip5, zeroMAC, ip5), nil, 4, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := conn.WriteTo(tt.packet, nil); err != tt.wantErr {
				t.Errorf("TestHandler_ForceIPChange:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)
			if len(h.table.macTable) != tt.wantLen {
				h.PrintTable()
				t.Errorf("TestHandler_ForceIPChange:%s table len = %v, wantLen %v", tt.name, len(h.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := h.table.findByMAC(tt.packet.SenderHardwareAddr)
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("TestHandler_ForceIPChange:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
			}
		})
	}

	if entry := h.table.findVirtualIP(ip2); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip2")
	}
	if entry := h.table.findVirtualIP(ip3); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip3")
	}
	if entry := h.table.findVirtualIP(ip4); entry == nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip4")
	}
	if entry := h.table.findVirtualIP(ip5); entry != nil {
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip5")
	}
	if entry := h.table.findByIP(ip5); entry == nil || entry.State != StateNormal || len(entry.IPs()) != 4 {
		h.PrintTable()
		t.Errorf("TestHandler_ForceIPChange invalid virtual ip52 entry=%+v", entry)
	}
	cancel()
	wg.Wait()
}
