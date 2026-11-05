package l2tp

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestCallCallbacksRemainOrderedAcrossConcurrentClose(t *testing.T) {
	a := &blockingCallAudit{entered: make(chan struct{}), release: make(chan struct{})}
	tunnel := NewServerTunnel(func([]byte) error { return nil }, a)
	defer tunnel.Abort()
	tunnel.state = stateEstablished
	tunnel.peerTunnelID.Store(7)
	tunnel.calls[1] = &tunnelCall{localID: 1, peerID: 101, created: time.Now()}
	finished := make(chan struct{})
	go func() {
		tunnel.HandleInbound(marshalControl(tunnel.localTunnelID, 1, 0, 0, callConnected()))
		close(finished)
	}()
	<-a.entered
	tunnel.CloseCall(1, io.EOF)
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		t.Fatal("CDN callback overtook in-flight ICCN callback")
	}
	close(a.release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("reentrant callback dispatcher deadlocked")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed || len(a.order) != 2 || a.order[0] != "up" || a.order[1] != "closed" {
		t.Fatalf("wrong callback order: %v", a.order)
	}
}

type blockingCallAudit struct {
	mu               sync.Mutex
	entered, release chan struct{}
	closed           bool
	order            []string
}

func (a *blockingCallAudit) CallUp(uint16) {
	close(a.entered)
	<-a.release
	a.mu.Lock()
	a.order = append(a.order, "up")
	a.mu.Unlock()
}
func (a *blockingCallAudit) CallClosed(uint16, error) {
	a.mu.Lock()
	a.closed = true
	a.order = append(a.order, "closed")
	a.mu.Unlock()
}
func (*blockingCallAudit) CallData(uint16, []byte) {}
func (*blockingCallAudit) Closed(error)            {}

func TestCallCapacityRejectsNewCallWithoutClosingSiblings(t *testing.T) {
	a := &multiCallAudit{data: map[uint16][][]byte{}}
	var packets [][]byte
	tunnel := NewServerTunnel(func(b []byte) error { packets = append(packets, append([]byte(nil), b...)); return nil }, a)
	defer tunnel.Abort()
	tunnel.state = stateEstablished
	tunnel.peerTunnelID.Store(7)
	for id := uint16(1); id <= maxCallsPerTunnel; id++ {
		tunnel.calls[id] = &tunnelCall{localID: id, peerID: id, up: true}
	}
	tunnel.HandleInbound(marshalControl(tunnel.localTunnelID, 0, 0, 0, callRequest(600)))
	if tunnel.state != stateEstablished || a.tunnelClosed != 0 || len(tunnel.calls) != maxCallsPerTunnel {
		t.Fatal("call limit terminated sibling users")
	}
	h, err := parseHeader(packets[0])
	if err != nil || h.sessionID != 600 {
		t.Fatal("resource refusal addressed wrong user")
	}
	avps, err := parseAVPs(h.payload)
	if err != nil {
		t.Fatal(err)
	}
	mt, _ := messageType(avps)
	if mt != msgCDN || validateControl(mt, avps) != nil {
		t.Fatal("invalid per-call resource refusal")
	}
	if err := tunnel.SendCallPPP(1, []byte{1}); err != nil {
		t.Fatal(err)
	}
}

func TestIdleCryptoCleanupPreservesSiblingControlsAndReleasesLastPeer(t *testing.T) {
	s, p, policy := concurrentServerFixture(t)
	first := newConcurrentControl(t, s, p, policy, 41000, 1)
	second := newConcurrentControl(t, s, p, policy, 41001, 2)
	s.removeControl(first, io.EOF)
	s.removePeerIfIdle(p, errors.New("idle cleanup"), true)
	if p.closed || second.closed {
		t.Fatal("idle cleanup removed shared carrier with live sibling")
	}
	s.removeControl(second, io.EOF)
	s.removePeerIfIdle(p, errors.New("idle cleanup"), true)
	if !p.closed || len(s.byCookie) != 0 || len(s.bySPI) != 0 || len(s.byTunnel) != 0 || len(s.byInitial) != 0 {
		t.Fatal("last control retained crypto indexes")
	}
}
