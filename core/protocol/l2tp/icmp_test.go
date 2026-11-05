//go:build linux && with_gvisor

package l2tp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	N "github.com/sagernet/sing/common/network"
)

type icmpTestRouter struct {
	adapter.Router
	match func(adapter.InboundContext, []byte) adapter.PreMatchResult
}

func (r *icmpTestRouter) PreMatch(m adapter.InboundContext, packet []byte) adapter.PreMatchResult {
	return r.match(m, packet)
}

func TestSessionICMPPolicyAndUserIdentity(t *testing.T) {
	port := newICMPTestPort()
	for _, tc := range []struct {
		name   string
		result adapter.PreMatchResult
		want   tun.FlowAction
	}{
		{"forward", adapter.PreMatchResult{Action: adapter.PreMatchFlow, Outbound: port}, tun.ActionFlow},
		{"bypass-with-port", adapter.PreMatchResult{Action: adapter.PreMatchBypass, Outbound: port}, tun.ActionFlow},
		{"reject", adapter.PreMatchResult{Action: adapter.PreMatchReject}, tun.ActionReject},
		{"drop", adapter.PreMatchResult{Action: adapter.PreMatchDrop}, tun.ActionDrop},
		{"unsupported-outbound", adapter.PreMatchResult{Action: adapter.PreMatchFlow, Outbound: &icmpTestNonPort{}}, tun.ActionReject},
		{"no-flow", adapter.PreMatchResult{Action: adapter.PreMatchContinue}, tun.ActionReject},
		{"bypass-without-port", adapter.PreMatchResult{Action: adapter.PreMatchBypass}, tun.ActionReject},
		{"no-outbound", adapter.PreMatchResult{Action: adapter.PreMatchFlow}, tun.ActionReject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			router := &icmpTestRouter{match: func(m adapter.InboundContext, packet []byte) adapter.PreMatchResult {
				called = true
				if m.User != "alice" || m.Inbound != "vpn" || m.InboundType != Type || m.Network != N.NetworkICMP {
					t.Fatalf("lost ICMP routing identity: %+v", m)
				}
				if m.Source.Port != 0 || m.Destination.Port != 0 || m.Source.Addr.String() != "10.20.0.2" || m.Destination.Addr.String() != "183.2.172.177" {
					t.Fatalf("ICMP identifier treated as network port: %+v", m)
				}
				return tc.result
			}}
			h := &sessionHandler{inbound: &Inbound{Adapter: inbound.NewAdapter(Type, "vpn"), router: router, logger: log.NewNOPFactory().Logger()}, user: "alice", address: netip.MustParseAddr("10.20.0.2")}
			v := h.JudgeFlow(1, netip.MustParseAddrPort("10.20.0.2:123"), netip.MustParseAddrPort("183.2.172.177:123"), nil)
			if !called || v.Action != tc.want {
				t.Fatalf("called=%v action=%v want=%v", called, v.Action, tc.want)
			}
			called = false
			if v := h.JudgeFlow(1, netip.MustParseAddrPort("10.20.0.3:123"), netip.MustParseAddrPort("183.2.172.177:123"), nil); v.Action != tun.ActionDrop || called {
				t.Fatal("spoofed ICMP source reached router")
			}
			for _, protocol := range []uint8{6, 17} {
				if v := h.JudgeFlow(protocol, netip.MustParseAddrPort("10.20.0.2:80"), netip.MustParseAddrPort("183.2.172.177:80"), nil); v.Action != tun.ActionAccept || called {
					t.Fatal("TCP/UDP routing path changed")
				}
			}
		})
	}
}

type icmpTestNonPort struct{ adapter.Outbound }

func TestSessionStackICMPActualRepliesAndConcurrentUsers(t *testing.T) {
	port := newICMPTestPort()
	users := map[string]netip.Addr{"alice": netip.MustParseAddr("10.20.0.2"), "bob": netip.MustParseAddr("10.20.0.3")}
	trackers := map[string]*icmpTestTracker{"alice": {}, "bob": {}}
	matches := make(chan adapter.InboundContext, 4)
	router := &icmpTestRouter{match: func(m adapter.InboundContext, _ []byte) adapter.PreMatchResult {
		matches <- m
		return adapter.PreMatchResult{Action: adapter.PreMatchFlow, Outbound: port, NewTracker: func() tun.FlowTracker { return trackers[m.User] }}
	}}
	in := &Inbound{Adapter: inbound.NewAdapter(Type, "vpn"), router: router, logger: log.NewNOPFactory().Logger()}
	destination := netip.MustParseAddr("183.2.172.177")
	devices := map[string]*packetDevice{}
	replies := map[string]<-chan []byte{}
	requests := map[string][]byte{}
	forwardedRequests := map[string][]byte{}
	for _, user := range []string{"alice", "bob"} {
		d, err := newSessionDevice(context.Background(), in, user, users[user], netip.MustParsePrefix("10.20.0.1/24"), 1400)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		devices[user] = d
		replies[user] = readICMPTestDevice(d)
		// Same destination, identifier and sequence on two accounts.
		request := icmpTestPacket(users[user], destination, 8, 123, 1, []byte(user))
		requests[user] = request
		if _, err = d.Write(request); err != nil {
			t.Fatal(err)
		}
		select {
		case forwarded := <-port.packets:
			if len(forwarded) != len(request) || !bytes.Equal(forwarded[28:], request[28:]) || !bytes.Equal(forwarded[16:20], destination.AsSlice()) {
				t.Fatal("outbound ICMP destination/payload changed")
			}
			forwardedRequests[user] = forwarded
		case <-time.After(time.Second):
			t.Fatal("ICMP request never reached selected outbound")
		}
		select {
		case m := <-matches:
			if m.User != user || m.Source.Port != 0 || m.Destination.Port != 0 {
				t.Fatalf("wrong user policy metadata: %+v", m)
			}
		case <-time.After(time.Second):
			t.Fatal("missing ICMP policy match")
		}
	}
	// Request arrival at the stack must not manufacture an Echo Reply.
	for _, user := range []string{"alice", "bob"} {
		assertNoICMPTestReply(t, replies[user])
	}
	for _, user := range []string{"bob", "alice"} {
		forwarded := forwardedRequests[user]
		source, _ := netip.AddrFromSlice(forwarded[12:16])
		outboundReply := icmpTestPacket(destination, source, 0, binary.BigEndian.Uint16(forwarded[24:26]), 1, []byte(user))
		reply := icmpTestPacket(destination, users[user], 0, 123, 1, []byte(user))
		if !port.reply(outboundReply) {
			t.Fatal("outbound return path did not consume actual reply")
		}
		select {
		case got := <-replies[user]:
			if !bytes.Equal(got, reply) {
				t.Fatalf("%s wrong ICMP reply: %x", user, got)
			}
		case <-time.After(time.Second):
			t.Fatal("actual ICMP reply not delivered")
		}
		other := "alice"
		if user == other {
			other = "bob"
		}
		assertNoICMPTestReply(t, replies[other])
		tracker := trackers[user]
		if tracker.forward.Load() != int64(len(requests[user])) || tracker.reverse.Load() != int64(len(reply)) {
			t.Fatal("ICMP flow tracker lost packet counts")
		}
	}
	devices["alice"].Close()
	if trackers["alice"].closed.Load() != 1 || port.returnCount() != 1 {
		t.Fatal("closing one PPP device retained ICMP return path or tracker")
	}
	// Existing Bob flow still forwards after Alice's device is closed.
	request := icmpTestPacket(users["bob"], destination, 8, 123, 2, []byte("bob again"))
	devices["bob"].Write(request)
	select {
	case got := <-port.packets:
		if len(got) != len(request) || !bytes.Equal(got[28:], request[28:]) {
			t.Fatal("sibling ICMP flow crossed users")
		}
	case <-time.After(time.Second):
		t.Fatal("closing sibling stopped remaining ICMP flow")
	}
}

func TestSessionStackICMPDoesNotFakeRepliesOnUnavailableRoute(t *testing.T) {
	for _, kind := range []string{"continue", "reject", "drop", "unsupported", "fixed-address-port", "attach-failure"} {
		t.Run(kind, func(t *testing.T) {
			port := newICMPTestPort()
			result := adapter.PreMatchResult{Action: adapter.PreMatchFlow, Outbound: port}
			switch kind {
			case "continue":
				result.Action = adapter.PreMatchContinue
			case "reject":
				result.Action = adapter.PreMatchReject
			case "drop":
				result.Action = adapter.PreMatchDrop
			case "unsupported":
				result.Outbound = &icmpTestNonPort{}
			case "fixed-address-port":
				port.address = netip.MustParseAddr("192.0.2.1")
			case "attach-failure":
				port.attachErr = errors.New("return path unavailable")
			}
			router := &icmpTestRouter{match: func(adapter.InboundContext, []byte) adapter.PreMatchResult { return result }}
			in := &Inbound{Adapter: inbound.NewAdapter(Type, "vpn"), router: router, logger: log.NewNOPFactory().Logger()}
			d, err := newSessionDevice(context.Background(), in, "alice", netip.MustParseAddr("10.20.0.2"), netip.MustParsePrefix("10.20.0.1/24"), 1400)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			replies := readICMPTestDevice(d)
			d.Write(icmpTestPacket(netip.MustParseAddr("10.20.0.2"), netip.MustParseAddr("183.2.172.177"), 8, 123, 1, []byte("ping")))
			if kind == "drop" {
				assertNoICMPTestReply(t, replies)
			} else {
				assertNoICMPTestEchoReply(t, replies)
			}
			select {
			case <-port.packets:
				t.Fatal("unavailable route forwarded ICMP")
			default:
			}
		})
	}
}

func TestSessionStackICMPRealPingPort(t *testing.T) {
	if os.Getenv("SUI_L2TP_ICMP_INTEGRATION") != "1" {
		t.Skip("requires permission to use local ICMP sockets")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	logger := log.NewNOPFactory().Logger()
	port := ping.NewPort(ctx, logger, nil, time.Second)
	defer port.Close()
	router := &icmpTestRouter{match: func(m adapter.InboundContext, _ []byte) adapter.PreMatchResult {
		if m.User != "alice" || m.Network != N.NetworkICMP {
			t.Fatalf("real ping lost routing identity: %+v", m)
		}
		return adapter.PreMatchResult{Action: adapter.PreMatchFlow, Outbound: &icmpTestOutboundPort{Port: port}, Destination: netip.MustParseAddrPort("127.0.0.1:0")}
	}}
	in := &Inbound{Adapter: inbound.NewAdapter(Type, "vpn"), router: router, logger: logger}
	address := netip.MustParseAddr("10.20.0.2")
	d, err := newSessionDevice(ctx, in, "alice", address, netip.MustParsePrefix("10.20.0.1/24"), 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// Packet metadata targets a routable-looking address so it exercises the
	// forward dispatcher; policy DNAT sends the actual ping to this host only.
	destination := netip.MustParseAddr("198.18.0.1")
	payload := []byte("l2tp-real-icmp")
	d.Write(icmpTestPacket(address, destination, 8, 123, 1, payload))
	out := readICMPTestDevice(d)
	select {
	case b := <-out:
		if len(b) < 28 || b[20] != 0 || !bytes.Equal(b[12:16], destination.AsSlice()) || !bytes.Equal(b[16:20], address.AsSlice()) || binary.BigEndian.Uint16(b[24:26]) != 123 || !bytes.Equal(b[28:], payload) {
			t.Fatalf("invalid real ICMP reply: %x", b)
		}
	case <-ctx.Done():
		t.Fatal("real local ping reply not delivered")
	}
}

type icmpTestOutboundPort struct {
	adapter.Outbound
	tun.Port
}

func readICMPTestDevice(d *packetDevice) <-chan []byte {
	out := make(chan []byte, 16)
	go func() {
		b := make([]byte, 65535)
		for {
			n, err := d.Read(b)
			if err != nil {
				return
			}
			out <- bytes.Clone(b[:n])
		}
	}()
	return out
}
func assertNoICMPTestReply(t *testing.T, out <-chan []byte) {
	t.Helper()
	select {
	case b := <-out:
		t.Fatalf("unexpected synthetic or cross-user reply: %x", b)
	case <-time.After(30 * time.Millisecond):
	}
}

func assertNoICMPTestEchoReply(t *testing.T, out <-chan []byte) {
	t.Helper()
	timer := time.NewTimer(30 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case b := <-out:
			if len(b) > 20 && b[20] == 0 {
				t.Fatalf("synthetic echo reply for unavailable route: %x", b)
			}
		case <-timer.C:
			return
		}
	}
}

func icmpTestPacket(source, destination netip.Addr, typ byte, id, seq uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	b[8] = 64
	b[9] = 1
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], source.AsSlice())
	copy(b[16:20], destination.AsSlice())
	b[20] = typ
	binary.BigEndian.PutUint16(b[24:26], id)
	binary.BigEndian.PutUint16(b[26:28], seq)
	copy(b[28:], payload)
	binary.BigEndian.PutUint16(b[22:24], icmpTestChecksum(b[20:]))
	binary.BigEndian.PutUint16(b[10:12], icmpTestChecksum(b[:20]))
	return b
}
func icmpTestChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

type icmpTestPort struct {
	adapter.Outbound
	mu        sync.Mutex
	returns   map[tun.Return]bool
	packets   chan []byte
	address   netip.Addr
	attachErr error
}

func newICMPTestPort() *icmpTestPort {
	return &icmpTestPort{returns: map[tun.Return]bool{}, packets: make(chan []byte, 16), address: netip.IPv4Unspecified()}
}
func (p *icmpTestPort) PortAddresses() (netip.Addr, netip.Addr) {
	return p.address, netip.IPv6Unspecified()
}
func (*icmpTestPort) PortMTU() uint32 { return 0 }
func (p *icmpTestPort) AttachReturn(r tun.Return) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.attachErr != nil {
		return p.attachErr
	}
	p.returns[r] = true
	return nil
}
func (p *icmpTestPort) DetachReturn(r tun.Return) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.returns, r)
	return nil
}
func (p *icmpTestPort) WritePackets(packets [][]byte) error {
	for _, b := range packets {
		p.packets <- bytes.Clone(b)
	}
	return nil
}
func (p *icmpTestPort) returnCount() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.returns) }
func (p *icmpTestPort) reply(b []byte) bool {
	p.mu.Lock()
	var paths []tun.Return
	for r := range p.returns {
		paths = append(paths, r)
	}
	p.mu.Unlock()
	for _, r := range paths {
		if len(r.ReturnPackets([][]byte{bytes.Clone(b)})) == 0 {
			return true
		}
	}
	return false
}

type icmpTestTracker struct{ forward, reverse, closed atomic.Int64 }

func (*icmpTestTracker) AttachFlow(tun.FlowHandle)       {}
func (t *icmpTestTracker) CountForward(n int)            { t.forward.Add(int64(n)) }
func (t *icmpTestTracker) CountReverse(n int)            { t.reverse.Add(int64(n)) }
func (*icmpTestTracker) FlowEstablished()                {}
func (t *icmpTestTracker) CloseFlow(tun.FlowCloseReason) { t.closed.Add(1) }
