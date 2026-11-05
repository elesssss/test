package l2tp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wanan9999/veepin/dataplane"
	"github.com/wanan9999/veepin/internal/ikev1"
	"github.com/wanan9999/veepin/internal/ikev2/esp"
)

type multiCallAudit struct {
	up           []uint16
	data         map[uint16][][]byte
	closed       []uint16
	tunnelClosed int
}

func (a *multiCallAudit) CallUp(id uint16) { a.up = append(a.up, id) }
func (a *multiCallAudit) CallData(id uint16, b []byte) {
	a.data[id] = append(a.data[id], bytes.Clone(b))
}
func (a *multiCallAudit) CallClosed(id uint16, err error) { a.closed = append(a.closed, id) }
func (a *multiCallAudit) Closed(error)                    { a.tunnelClosed++ }

func callRequest(peer uint16) []byte {
	var b avpBuilder
	b.addUint16(avpMessageType, msgICRQ)
	b.addUint16(avpAssignedSessionID, peer)
	b.addUint32(avpCallSerialNumber, uint32(peer))
	return b.bytes()
}
func callConnected() []byte {
	var b avpBuilder
	b.addUint16(avpMessageType, msgICCN)
	b.addUint32(avpTxConnectSpeed, 100000)
	b.addUint32(avpFramingType, 1)
	return b.bytes()
}

func TestMultipleCallsShareControlSequenceButNotUsersOrData(t *testing.T) {
	audit := &multiCallAudit{data: map[uint16][][]byte{}}
	var sent [][]byte
	tunnel := NewServerTunnel(func(b []byte) error { sent = append(sent, bytes.Clone(b)); return nil }, audit)
	defer tunnel.Abort()
	tunnel.state = stateEstablished
	tunnel.peerTunnelID.Store(7)
	var ns, nr uint16
	var ids []uint16
	for _, peer := range []uint16{101, 102, 103} {
		tunnel.HandleInbound(marshalControl(tunnel.localTunnelID, 0, ns, nr, callRequest(peer)))
		ns++
		var selected uint16
		for id, c := range tunnel.calls {
			if c.peerID == peer {
				selected = id
			}
		}
		if selected == 0 {
			t.Fatal("no independent Session ID")
		}
		nr = tunnel.sentNS
		tunnel.HandleInbound(marshalControl(tunnel.localTunnelID, selected, ns, nr, callConnected()))
		ns++
		ids = append(ids, selected)
	}
	if len(audit.up) != 3 || len(tunnel.calls) != 3 {
		t.Fatal("new call replaced another call")
	}
	for i, id := range ids {
		payload := []byte{byte(i), 9}
		tunnel.HandleInbound(marshalData(tunnel.localTunnelID, id, payload))
		if len(audit.data[id]) != 1 {
			t.Fatal("Session ID data was not demultiplexed")
		}
		if err := tunnel.SendCallPPP(id, payload); err != nil {
			t.Fatal(err)
		}
		h, err := parseHeader(sent[len(sent)-1])
		if err != nil || h.sessionID != uint16(101+i) {
			t.Fatal("outbound PPP used another call ID")
		}
	}
	// CDN closes one PPP call, not the shared control tunnel.
	var b avpBuilder
	b.addUint16(avpMessageType, msgCDN)
	b.addUint16(avpResultCode, 1)
	b.addUint16(avpAssignedSessionID, 102)
	tunnel.HandleInbound(marshalControl(tunnel.localTunnelID, ids[1], ns, tunnel.sentNS, b.bytes()))
	if len(audit.closed) != 1 || audit.closed[0] != ids[1] || audit.tunnelClosed != 0 || tunnel.state != stateEstablished {
		t.Fatal("single CDN closed sibling calls")
	}
	for _, i := range []int{0, 2} {
		if err := tunnel.SendCallPPP(ids[i], []byte{1}); err != nil {
			t.Fatal("sibling call stopped")
		}
	}
	if err := tunnel.SendCallPPP(ids[1], []byte{1}); err == nil {
		t.Fatal("closed call admitted data")
	}
}

func concurrentServerFixture(t *testing.T) (*Server, *serverPeer, ikev1.TransportPolicy) {
	t.Helper()
	s := lifecycleServer(t)
	pool, gateway, err := dataplane.NewAddrPool("10.20.0.0/23")
	if err != nil {
		t.Fatal(err)
	}
	s.pool, s.gateway = pool, gateway
	s.cfg.PacketDeviceFactory = func(string, net.IP, uint16) (io.ReadWriteCloser, error) { return &testSessionDevice{}, nil }
	policy := ikev1.TransportPolicy{LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(10, 0, 0, 2), LocalPort: 1701}
	identity, err := makePeerIdentity([]byte{1, 0, 0, 0, 10, 0, 0, 2}, policy, net.IPv4(198, 51, 100, 1))
	if err != nil {
		t.Fatal(err)
	}
	p := &serverPeer{srv: s, cookie: [8]byte{1}, addr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 500}, nattAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}, identity: identity, done: make(chan struct{}), controls: map[*serverControl]bool{}}
	p.sas = map[uint32]timedSA{1: {sa: &esp.SA{SPIIn: 1, SPIOut: 2}, expires: time.Now().Add(time.Hour), transport: policy}}
	p.inSPI = 1
	p.sa = p.sas[1].sa
	s.byCookie[p.cookie] = p
	s.bySPI[1] = p
	return s, p, policy
}
func newConcurrentControl(t *testing.T, s *Server, p *serverPeer, policy ikev1.TransportPolicy, source, peerID uint16) *serverControl {
	t.Helper()
	key := controlKey{owner: p, identity: p.identity, source: source, destination: 1701, peerTunnel: peerID}
	control := &serverControl{srv: s, key: key, created: time.Now(), carriers: map[carrierKey]bool{}, calls: map[uint16]*serverCall{}, done: make(chan struct{})}
	control.tunnel = NewServerTunnel(func([]byte) error { return nil }, control)
	control.tunnel.state = stateEstablished
	control.tunnel.peerTunnelID.Store(uint32(peerID))
	for s.byTunnel[control.tunnel.localTunnelID] != nil {
		control.tunnel.localTunnelID++
		if control.tunnel.localTunnelID == 0 {
			control.tunnel.localTunnelID = 1
		}
	}
	s.byTunnel[control.tunnel.localTunnelID] = control
	s.byInitial[key] = control
	if !control.addCarrier(p, 1, policy, true) {
		t.Fatal("carrier not associated")
	}
	return control
}
func startConcurrentCall(control *serverControl, id uint16) {
	control.tunnel.mu.Lock()
	control.tunnel.calls[id] = &tunnelCall{localID: id, peerID: id, up: true, created: time.Now()}
	control.tunnel.mu.Unlock()
	control.CallUp(id)
}
func TestSharedSAHasIndependentTunnelAndCallAddresses(t *testing.T) {
	s, p, policy := concurrentServerFixture(t)
	var controls []*serverControl
	for i := range 3 {
		control := newConcurrentControl(t, s, p, policy, uint16(41000+i), uint16(10+i))
		startConcurrentCall(control, 1)
		controls = append(controls, control)
	}
	if len(s.byTunnel) != 3 || len(s.byIP) != 3 || s.callCount != 3 {
		t.Fatal("shared SA replaced a tunnel/address")
	}
	addresses := map[string]bool{}
	for i, control := range controls {
		call := control.calls[1]
		addresses[call.address.String()] = true
		call.mu.Lock()
		call.username = fmt.Sprintf("user-%d", i)
		call.ready = true
		call.mu.Unlock()
	}
	if len(addresses) != 3 {
		t.Fatal("different users reused an address")
	}
	controls[1].calls[1].beginDrain(errors.New("single user failure"))
	if controls[0].calls[1].draining || controls[2].calls[1].draining || p.closed {
		t.Fatal("one user failure closed shared carrier")
	}
}
func TestControlCanUseMatchingAlternateSAButNotDifferentIdentity(t *testing.T) {
	s, p, policy := concurrentServerFixture(t)
	control := newConcurrentControl(t, s, p, policy, 41000, 10)
	other := &serverPeer{srv: s, cookie: [8]byte{2}, identity: p.identity, controls: map[*serverControl]bool{}, nattAddr: cloneUDPAddr(p.nattAddr), sas: map[uint32]timedSA{3: {sa: &esp.SA{SPIIn: 3, SPIOut: 4}, expires: time.Now().Add(time.Hour), transport: policy}}, inSPI: 3, done: make(chan struct{})}
	other.sa = other.sas[3].sa
	s.byCookie[other.cookie] = other
	s.bySPI[3] = other
	if !control.addCarrier(other, 3, policy, true) {
		t.Fatal("matching alternate SA rejected")
	}
	bad := &serverPeer{identity: other.identity, controls: map[*serverControl]bool{}, sas: other.sas, nattAddr: cloneUDPAddr(other.nattAddr)}
	bad.identity.id = "another identity"
	if control.addCarrier(bad, 3, policy, true) {
		t.Fatal("different IKE identity acquired tunnel")
	}
	s.removePeer(p, errors.New("one SA deleted"))
	if control.closed || other.closed {
		t.Fatal("deleting first SA closed tunnel with live alternate")
	}
	s.removePeer(other, errors.New("last SA deleted"))
	if !control.closed {
		t.Fatal("tunnel retained without authenticated carrier")
	}
}
func Test254CallsKeepIndependentAddresses(t *testing.T) {
	s, p, policy := concurrentServerFixture(t)
	control := newConcurrentControl(t, s, p, policy, 41000, 10)
	for i := 1; i <= 254; i++ {
		startConcurrentCall(control, uint16(i))
	}
	if s.callCount != 254 || len(s.byIP) != 254 {
		t.Fatalf("call/address capacity: %d/%d", s.callCount, len(s.byIP))
	}
	for _, call := range control.calls {
		if s.byIP[binary.BigEndian.Uint32(call.address.To4())] != call {
			t.Fatal("address index crossed calls")
		}
	}
	// Synthetic allocation/ownership coverage, not a network load benchmark.
}
