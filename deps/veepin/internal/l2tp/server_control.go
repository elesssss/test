package l2tp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/wanan9999/veepin/internal/ikev1"
)

// Identity combines the authenticated IKE ID and transport's original IPv4
// hosts. NAT endpoints alone are never sufficient to move a control tunnel.
type peerIdentity struct {
	id                          string
	local, remote, publicRemote netip.Addr
	valid                       bool
}

func makePeerIdentity(id []byte, policy ikev1.TransportPolicy, public net.IP) (peerIdentity, error) {
	if len(id) < 5 {
		return peerIdentity{}, errors.New("l2tp: missing authenticated IKE identity")
	}
	local, lok := netip.AddrFromSlice(policy.LocalIP.To4())
	remote, rok := netip.AddrFromSlice(policy.PeerIP.To4())
	external, eok := netip.AddrFromSlice(public.To4())
	if !lok || !rok || !eok {
		return peerIdentity{}, errors.New("l2tp: missing original transport addresses")
	}
	// Protocol/port selectors are not part of the phase-one identity value.
	return peerIdentity{id: string(append([]byte{id[0]}, id[4:]...)), local: local, remote: remote, publicRemote: external, valid: true}, nil
}

type controlKey struct {
	owner                           *serverPeer
	identity                        peerIdentity
	source, destination, peerTunnel uint16
}
type carrierKey struct {
	peer *serverPeer
	spi  uint32
}
type serverControl struct {
	srv              *Server
	key              controlKey
	tunnel           *Tunnel
	mu               sync.Mutex
	closed, draining bool
	created          time.Time
	peerHistory      map[*serverPeer]bool
	current          carrierKey
	carriers         map[carrierKey]bool
	calls            map[uint16]*serverCall
	done             chan struct{}
	drainTimer       *time.Timer
}

func policyMatchesControl(policy ikev1.TransportPolicy, key controlKey) bool {
	return (policy.PeerPort == 0 || policy.PeerPort == key.source) && (policy.LocalPort == 0 || policy.LocalPort == key.destination) &&
		net.IP(key.identity.local.AsSlice()).Equal(policy.LocalIP) && net.IP(key.identity.remote.AsSlice()).Equal(policy.PeerIP)
}

func (s *Server) routeL2TP(p *serverPeer, spi uint32, identity peerIdentity, policy ikev1.TransportPolicy, source, destination uint16, packet []byte) {
	h, err := parseHeader(packet)
	if err != nil || !identity.valid {
		return
	}
	var initial bool
	var peerID uint16
	if h.isControl && h.tunnelID == 0 && h.sessionID == 0 && h.ns == 0 {
		avps, e := parseAVPs(h.payload)
		if e != nil {
			return
		}
		mt, ok := messageType(avps)
		if !ok || mt != msgSCCRQ || validateControl(mt, avps) != nil {
			return
		}
		peerID, _ = findUint16(avps, avpAssignedTunnelID)
		initial = true
	}
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return
	default:
	}
	var control *serverControl
	created := false
	if initial {
		key := controlKey{owner: p, identity: identity, source: source, destination: destination, peerTunnel: peerID}
		control = s.byInitial[key]
		if control != nil {
			control.mu.Lock()
			closing := control.closed || control.draining
			control.mu.Unlock()
			if closing {
				control = nil
			}
		}
		if control == nil {
			if len(s.byTunnel) >= maxServerTunnels {
				s.mu.Unlock()
				s.logger.Warnf("l2tp: control tunnel capacity exhausted")
				return
			}
			control = &serverControl{srv: s, key: key, created: time.Now(), carriers: map[carrierKey]bool{}, calls: map[uint16]*serverCall{}, done: make(chan struct{})}
			control.tunnel = NewServerTunnel(control.sendL2TP, control)
			// Tunnel IDs are global here, so packets crossing compatible SAs can
			// still reach their original tunnel without randomized collisions.
			id := control.tunnel.localTunnelID
			for attempts := 0; s.byTunnel[id] != nil; attempts++ {
				if attempts >= 65535 {
					s.mu.Unlock()
					return
				}
				id++
				if id == 0 {
					id = 1
				}
			}
			control.tunnel.localTunnelID = id
			s.byTunnel[id] = control
			s.byInitial[key] = control
			created = true
		}
	} else {
		control = s.byTunnel[h.tunnelID]
	}
	if control == nil || control.key.identity != identity || control.key.source != source || control.key.destination != destination || !policyMatchesControl(policy, control.key) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if !control.addCarrier(p, spi, policy, true) {
		if created {
			s.removeControl(control, errors.New("l2tp: initial IPsec carrier unavailable"))
		}
		return
	}
	if created {
		go control.monitor()
		s.logger.Printf("l2tp: control tunnel registered cookie=%x SPI=%#x tunnel=%d peer-tunnel=%d UDP=%d->%d", p.cookie, spi, control.tunnel.LocalTunnelID(), peerID, source, destination)
	}
	control.tunnel.HandleInbound(packet)
}

func (t *serverControl) addCarrier(p *serverPeer, spi uint32, policy ikev1.TransportPolicy, observed bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !policyMatchesControl(policy, t.key) {
		return false
	}
	// A fresh phase-one SA is not automatically a renewal: multiple accounts on
	// one router can share IDs, selectors and a NAT endpoint. Cross-peer binding
	// requires a packet addressing this existing tunnel. Known peers may add their
	// own replacement Quick Mode SAs without disturbing sibling tunnels.
	if !observed && !t.peerHistory[p] {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.sas[spi]
	if p.closed || p.identity != t.key.identity || !ok || !time.Now().Before(entry.expires) {
		return false
	}
	key := carrierKey{peer: p, spi: spi}
	if len(t.carriers) >= 512 && !t.carriers[key] {
		return false
	}
	if t.peerHistory == nil {
		t.peerHistory = map[*serverPeer]bool{}
	}
	if len(t.peerHistory) >= 512 && !t.peerHistory[p] {
		return false
	}
	knownPeer := t.peerHistory[p]
	t.carriers[key] = true
	t.peerHistory[p] = true
	if p.controls == nil {
		p.controls = map[*serverControl]bool{}
	}
	p.controls[t] = true
	p.used = true
	// Prefer the newly established/current SA, not a late packet from an old
	// overlapping SA. The client IPsec stack commonly selects its newest SA.
	// A known peer's old overlapping SA must not become preferred again just
	// because a delayed packet arrives after a fresh Main Mode peer was observed.
	if t.current.peer == nil || (!t.carriers[t.current]) || spi == p.inSPI && (t.current.peer == p || observed && !knownPeer) {
		t.current = key
	}
	return true
}

func (t *serverControl) carrierLocked() (carrierKey, timedSA, *net.UDPAddr, bool) {
	keys := make([]carrierKey, 0, len(t.carriers)+1)
	keys = append(keys, t.current)
	for key := range t.carriers {
		if key != t.current {
			keys = append(keys, key)
		}
	}
	for _, key := range keys {
		if key.peer == nil || !t.carriers[key] {
			continue
		}
		key.peer.mu.Lock()
		entry, ok := key.peer.sas[key.spi]
		closed := key.peer.closed
		to := cloneUDPAddr(key.peer.nattAddr)
		identity := key.peer.identity
		key.peer.mu.Unlock()
		if !closed && ok && identity == t.key.identity && time.Now().Before(entry.expires) && policyMatchesControl(entry.transport, t.key) {
			t.current = key
			return key, entry, to, true
		}
		delete(t.carriers, key)
	}
	return carrierKey{}, timedSA{}, nil, false
}
func (t *serverControl) sendL2TP(packet []byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return net.ErrClosed
	}
	key, entry, to, ok := t.carrierLocked()
	t.mu.Unlock()
	if !ok {
		return errors.New("l2tp: no live IPsec carrier for control tunnel")
	}
	if entry.sa.NeedsRekey() && key.peer.ike != nil {
		key.peer.ike.RequestRekey()
	}
	out, err := entry.sa.Encapsulate(wrapUDP(packet, t.key.destination, t.key.source), ipProtoUDP)
	if err != nil {
		return err
	}
	_, err = t.srv.nattConn.WriteToUDP(out, to)
	return err
}
func (t *serverControl) detachCarrier(p *serverPeer, err error) {
	t.mu.Lock()
	for key := range t.carriers {
		if key.peer == p {
			delete(t.carriers, key)
		}
	}
	delete(t.peerHistory, p)
	_, _, _, ok := t.carrierLocked()
	closed := t.closed
	t.mu.Unlock()
	if !ok && !closed {
		t.srv.removeControl(t, err)
	}
}
func (t *serverControl) detachUnavailableCarrier(p *serverPeer) {
	t.mu.Lock()
	p.mu.Lock()
	for key := range t.carriers {
		if key.peer != p {
			continue
		}
		entry, ok := p.sas[key.spi]
		if p.closed || !ok || !time.Now().Before(entry.expires) {
			delete(t.carriers, key)
		}
	}
	p.mu.Unlock()
	_, _, _, ok := t.carrierLocked()
	closed := t.closed
	t.mu.Unlock()
	if !ok && !closed {
		t.srv.removeControl(t, errors.New("l2tp: all IPsec carriers expired or deleted"))
	}
}
func (s *Server) removeControl(t *serverControl, err error) {
	s.mu.Lock()
	if s.byTunnel[t.tunnel.LocalTunnelID()] != t {
		s.mu.Unlock()
		return
	}
	delete(s.byTunnel, t.tunnel.LocalTunnelID())
	if s.byInitial[t.key] == t {
		delete(s.byInitial, t.key)
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		s.mu.Unlock()
		return
	}
	t.closed = true
	close(t.done)
	if t.drainTimer != nil {
		t.drainTimer.Stop()
	}
	calls := make([]*serverCall, 0, len(t.calls))
	for _, call := range t.calls {
		calls = append(calls, call)
	}
	peers := t.peerHistory
	t.peerHistory = nil
	t.carriers = nil
	t.mu.Unlock()
	s.mu.Unlock()
	for p := range peers {
		p.mu.Lock()
		delete(p.controls, t)
		p.mu.Unlock()
	}
	for _, call := range calls {
		s.removeCall(call, err)
	}
	t.tunnel.Abort()
	s.logger.Printf("l2tp: control tunnel=%d gone: %v", t.tunnel.LocalTunnelID(), err)
}
func (t *serverControl) Closed(err error) {
	if errors.Is(err, ErrControlTimeout) {
		t.srv.removeControl(t, err)
		return
	}
	t.mu.Lock()
	if t.closed || t.draining {
		t.mu.Unlock()
		return
	}
	t.draining = true
	calls := make([]*serverCall, 0, len(t.calls))
	for _, c := range t.calls {
		calls = append(calls, c)
	}
	t.drainTimer = time.AfterFunc(31*time.Second, func() { t.srv.removeControl(t, err) })
	t.mu.Unlock()
	for _, c := range calls {
		c.stopData()
	}
}
func (t *serverControl) monitor() {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-timer.C:
			t.tunnel.mu.Lock()
			up := t.tunnel.state == stateEstablished
			t.tunnel.mu.Unlock()
			if !up {
				t.srv.removeControl(t, errors.New("l2tp: control setup timed out"))
				return
			}
		case <-ticker.C:
			t.tunnel.expireCalls(time.Now())
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-t.done:
					cancel()
				case <-ctx.Done():
				}
			}()
			err := t.tunnel.SendHello(ctx)
			cancel()
			if err != nil {
				t.mu.Lock()
				closing := t.closed || t.draining
				t.mu.Unlock()
				if !closing {
					t.srv.removeControl(t, fmt.Errorf("l2tp: liveness: %w", err))
				}
				return
			}
		}
	}
}

// Initial peer tunnel IDs and all tunnel identities remain private to Server.
// The only global key visible on the wire is our nonzero Tunnel ID; it is
// still checked against authenticated client and transport selectors above.
var _ CallHandler = (*serverControl)(nil)
