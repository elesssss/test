package l2tp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wanan9999/veepin/internal/ikev1"
	"github.com/wanan9999/veepin/internal/ikev2/esp"
	"github.com/wanan9999/veepin/internal/mschap"
	"github.com/wanan9999/veepin/internal/ppp"
)

func TestSharedControlAuthenticatesIndependentPPPUsersAndRedials(t *testing.T) {
	s, p, policy := concurrentServerFixture(t)
	s.cfg.Users = map[string]string{"alice": "a", "bob": "b"}
	devices := make(chan sessionDeviceRecord, 4)
	s.cfg.PacketDeviceFactory = func(user string, ip net.IP, _ uint16) (io.ReadWriteCloser, error) {
		d := newConcurrentDevice()
		devices <- sessionDeviceRecord{user, bytes.Clone(ip), d}
		return d, nil
	}
	control := newConcurrentControl(t, s, p, policy, 41000, 10)
	out := make(chan []byte, 256)
	control.tunnel.send = func(b []byte) error { out <- bytes.Clone(b); return nil }
	clients := map[uint16]*ppp.Session{}
	handlers := map[uint16]*sharedPPPHandler{}
	var ns uint16
	pump := func(done func() bool) {
		t.Helper()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		for !done() {
			select {
			case packet := <-out:
				h, err := parseHeader(packet)
				if err != nil {
					t.Fatal(err)
				}
				if h.isControl {
					control.tunnel.HandleInbound(marshalControl(control.tunnel.localTunnelID, 0, ns, h.ns+1, nil))
				} else if client := clients[h.sessionID]; client != nil {
					client.Receive(h.payload)
				}
			case <-deadline.C:
				t.Fatal("shared-control PPP exchange stalled")
			}
		}
	}
	add := func(peerID uint16, user, password string) uint16 {
		t.Helper()
		control.tunnel.HandleInbound(marshalControl(control.tunnel.localTunnelID, 0, ns, control.tunnel.sentNS, callRequest(peerID)))
		ns++
		var id uint16
		for key, call := range control.tunnel.calls {
			if call.peerID == peerID && !call.closed {
				id = key
			}
		}
		if id == 0 {
			t.Fatal("ICRQ did not allocate new call")
		}
		handler := &sharedPPPHandler{}
		client := ppp.New(user, password, sharedPPPTransport{control.tunnel, id}, handler)
		clients[peerID], handlers[peerID] = client, handler
		control.tunnel.HandleInbound(marshalControl(control.tunnel.localTunnelID, id, ns, control.tunnel.sentNS, callConnected()))
		ns++
		client.Start()
		pump(func() bool { return handler.up || handler.err != nil })
		if handler.err != nil {
			t.Fatal(handler.err)
		}
		return id
	}
	alice, bob := add(101, "alice", "a"), add(102, "bob", "b")
	a, b := <-devices, <-devices
	if a.user != "alice" || b.user != "bob" || a.ip.Equal(b.ip) {
		t.Fatal("shared SA/control authenticated users merged")
	}
	for _, id := range []uint16{alice, bob} {
		call := control.calls[id]
		call.mu.Lock()
		ready := call.ready
		call.mu.Unlock()
		if !ready {
			t.Fatal("PPP server did not reach network-up")
		}
	}
	up := makeIPv4(a.ip, s.gateway)
	control.tunnel.HandleInbound(marshalData(control.tunnel.localTunnelID, alice, ppp.EncapsulateIP(up)))
	assertPacket(t, "alice shared uplink", a.device.out, up)
	up = makeIPv4(b.ip, s.gateway)
	control.tunnel.HandleInbound(marshalData(control.tunnel.localTunnelID, bob, ppp.EncapsulateIP(up)))
	assertPacket(t, "bob shared uplink", b.device.out, up)
	// The other user's assigned source is not valid on Alice's Session ID.
	control.tunnel.HandleInbound(marshalData(control.tunnel.localTunnelID, alice, ppp.EncapsulateIP(up)))
	select {
	case <-a.device.out:
		t.Fatal("cross-user source admitted")
	default:
	}
	if n := s.KickUserSessions("bob"); n != 1 {
		t.Fatalf("kicked %d shared calls", n)
	}
	if control.closed || p.closed {
		t.Fatal("single-user kick removed shared tunnel/SA")
	}
	pump(func() bool { return len(control.tunnel.unacked) == 0 })
	// Peer can reuse its own Session ID after the old CDN is acknowledged;
	// the server's old local ID and IP remain quarantined until cleanup.
	bob2 := add(102, "bob", "b")
	b2 := <-devices
	if bob2 == bob || b2.ip.Equal(b.ip) {
		t.Fatal("redial reused draining local ID/address")
	}
	if control.calls[alice].ppp == nil || control.calls[bob2].username != "bob" {
		t.Fatal("redial replaced sibling PPP")
	}
	old := control.calls[bob]
	s.removeCall(old, io.EOF)
	s.removeCall(old, io.EOF)
	control.tunnel.expireCalls(time.Now().Add(time.Minute))
	if s.callCount != 2 || len(s.byIP) != 2 || control.tunnel.calls[bob] != nil {
		t.Fatal("old call cleanup damaged live redial")
	}
	var cdn avpBuilder
	cdn.addUint16(avpMessageType, msgCDN)
	cdn.addUint16(avpResultCode, 1)
	cdn.addUint16(avpAssignedSessionID, 101)
	control.tunnel.HandleInbound(marshalControl(control.tunnel.localTunnelID, alice, ns, control.tunnel.sentNS, cdn.bytes()))
	if control.closed || p.closed || control.calls[bob2].draining {
		t.Fatal("peer CDN stopped sibling user")
	}
	up = makeIPv4(b2.ip, s.gateway)
	control.tunnel.HandleInbound(marshalData(control.tunnel.localTunnelID, bob2, ppp.EncapsulateIP(up)))
	assertPacket(t, "redial survives sibling CDN", b2.device.out, up)
}

type sharedPPPTransport struct {
	tunnel *Tunnel
	id     uint16
}

func (tr sharedPPPTransport) SendPPP(b []byte) error {
	tr.tunnel.HandleInbound(marshalData(tr.tunnel.localTunnelID, tr.id, b))
	return nil
}

type sharedPPPHandler struct {
	up  bool
	err error
}

func (h *sharedPPPHandler) Authenticated([mschap.NTResponseLen]byte) {}
func (h *sharedPPPHandler) NetworkUp(ppp.IPConfig)                   { h.up = true }
func (h *sharedPPPHandler) Closed(err error)                         { h.err = err }

func TestInitialTunnelsAreScopedToCryptoPeerAndRedial(t *testing.T) {
	s, p, policy := concurrentServerFixture(t)
	tr := esp.Transform{EncrID: 12, EncrKeyLn: 128, IntegID: 2, EncKey: bytes.Repeat([]byte{1}, 16), IntegKey: bytes.Repeat([]byte{2}, 20)}
	p.sa.Out = tr
	p.sa.In = tr
	q := &serverPeer{srv: s, cookie: [8]byte{2}, identity: p.identity, addr: cloneUDPAddr(p.addr), nattAddr: cloneUDPAddr(p.nattAddr), sas: map[uint32]timedSA{}, controls: map[*serverControl]bool{}, done: make(chan struct{})}
	q.sa = &esp.SA{SPIIn: 3, SPIOut: 4, Out: tr, In: tr}
	q.inSPI = 3
	q.sas[3] = timedSA{sa: q.sa, expires: time.Now().Add(time.Hour), transport: policy}
	s.byCookie[q.cookie] = q
	s.bySPI[3] = q
	var b avpBuilder
	b.addUint16(avpMessageType, msgSCCRQ)
	b.add(avpProtocolVersion, []byte{1, 0})
	b.addUint32(avpFramingCapabilities, 3)
	b.add(avpHostName, []byte("ikuai"))
	b.addUint16(avpAssignedTunnelID, 7)
	initial := marshalControl(0, 0, 0, 0, b.bytes())
	s.routeL2TP(p, 1, p.identity, policy, 1701, 1701, initial)
	s.routeL2TP(q, 3, q.identity, policy, 1701, 1701, initial)
	if len(s.byTunnel) != 2 || len(s.byInitial) != 2 {
		t.Fatal("same identity, endpoint and peer tunnel ID merged independent logins")
	}
	var original *serverControl
	for _, c := range s.byTunnel {
		if c.key.owner == p {
			original = c
		}
	}
	if len(original.carriers) != 1 {
		t.Fatal("unobserved sibling SA attached")
	}
	s.routeL2TP(p, 1, p.identity, policy, 1701, 1701, initial)
	if len(s.byTunnel) != 2 {
		t.Fatal("SCCRQ retransmission duplicated tunnel")
	}
	original.tunnel.finishClose(io.EOF)
	s.routeL2TP(p, 1, p.identity, policy, 1701, 1701, initial)
	if len(s.byTunnel) != 3 {
		t.Fatal("redial was swallowed by closing tunnel tombstone")
	}
	replacement := s.byInitial[original.key]
	s.removeControl(original, io.EOF)
	if s.byInitial[original.key] != replacement {
		t.Fatal("late cleanup removed redial mapping")
	}
}

func TestSamePeerRekeyPreservesSharedCallsAndRejectsUnobservedSiblingSA(t *testing.T) {
	s, p, policy := concurrentServerFixture(t)
	control := newConcurrentControl(t, s, p, policy, 1701, 10)
	startConcurrentCall(control, 1)
	startConcurrentCall(control, 2)
	first, second := control.calls[1], control.calls[2]
	// Establishment on an unrelated matching peer is not proof of renewal.
	q := &serverPeer{srv: s, cookie: [8]byte{2}, addr: cloneUDPAddr(p.addr), nattAddr: cloneUDPAddr(p.nattAddr), done: make(chan struct{}), controls: map[*serverControl]bool{}}
	s.byCookie[q.cookie] = q
	result := ikev1.Result{PeerID: []byte{1, 0, 0, 0, 10, 0, 0, 2}, Transport: policy, InSPI: 3, OutSPI: 4, Lifetime: time.Hour}
	q.Established(result)
	if control.current.peer != p || len(control.carriers) != 1 || q.used {
		t.Fatal("matching fresh login hijacked an existing tunnel")
	}
	result.InSPI, result.OutSPI, result.Rekey = 5, 6, true
	p.Established(result)
	if control.current.peer != p || control.current.spi != 5 {
		t.Fatal("same-peer Quick Mode did not select new SA")
	}
	p.DeleteESP(2)
	if control.closed || control.calls[1] != first || control.calls[2] != second {
		t.Fatal("deleting overlapping old SA closed or replaced PPP calls")
	}
	// A packet addressing the original tunnel explicitly associates a fresh
	// Main Mode SA and allows data continuity after the old crypto peer expires.
	if !control.addCarrier(q, 3, policy, true) {
		t.Fatal("observed renewal rejected")
	}
	control.addCarrier(p, 5, policy, true)
	if control.current.peer != q {
		t.Fatal("late packet from retired peer rolled back carrier")
	}
	s.removePeer(p, errors.New("retired IKE SA"))
	if control.closed || control.current.peer != q {
		t.Fatal("retiring old crypto peer lost authenticated replacement")
	}
	if s.byIP[binary.BigEndian.Uint32(first.address.To4())] != first {
		t.Fatal("renewal changed user address ownership")
	}
}
