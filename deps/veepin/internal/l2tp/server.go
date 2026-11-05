package l2tp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wanan9999/veepin/dataplane"
	"github.com/wanan9999/veepin/internal/ikev1"
	"github.com/wanan9999/veepin/internal/ikev2/esp"
	"github.com/wanan9999/veepin/internal/vlog"
)

type ServerConfig struct {
	PacketDeviceFactory func(string, net.IP, uint16) (io.ReadWriteCloser, error)
	PSK                 []byte
	Users               map[string]string
	PublicIP            net.IP
	Pool                *dataplane.AddrPool
	Gateway             net.IP
	DNS                 []net.IP
	Shape, MTU          int
	Logger              *vlog.Logger
}

const (
	defaultShapeMTU  = 1400
	maxServerTunnels = 1024
	maxServerCalls   = 4096
	maxCryptoPeers   = 2048
)

// Crypto peers, L2TP control tunnels and authenticated PPP calls are separate.
// Several calls/tunnels may share one SA, or traverse matching SAs from the
// same authenticated client. Neither public IP nor NAT port identifies a user.
// Lock order: Server.mu -> serverControl.mu -> serverCall.mu. Crypto-peer locks
// are not held while acquiring Server.mu or calling IKE/Tunnel/PPP callbacks.
type Server struct {
	cfg               ServerConfig
	ikeConn, nattConn *dataplane.PacketConn
	tun               tunIO
	pool              *dataplane.AddrPool
	gateway           net.IP
	logger            *vlog.Logger
	gate              *dataplane.Gate
	mu                sync.Mutex
	byCookie          map[[8]byte]*serverPeer
	bySPI             map[uint32]*serverPeer
	byIP              map[uint32]*serverCall
	byTunnel          map[uint16]*serverControl
	byInitial         map[controlKey]*serverControl
	callCount         int
	serveErr          chan error
	done              chan struct{}
	closeOnce         sync.Once
}

func NewServer(ike, natt *net.UDPConn, tun tunIO, cfg ServerConfig) *Server {
	return &Server{cfg: cfg, ikeConn: dataplane.NewPacketConn(ike), nattConn: dataplane.NewPacketConn(natt), tun: tun, pool: cfg.Pool, gateway: cfg.Gateway, logger: cfg.Logger,
		gate: dataplane.NewGate(dataplane.AdmissionConfig{}), byCookie: map[[8]byte]*serverPeer{}, bySPI: map[uint32]*serverPeer{}, byIP: map[uint32]*serverCall{},
		byTunnel: map[uint16]*serverControl{}, byInitial: map[controlKey]*serverControl{}, done: make(chan struct{}), serveErr: make(chan error, 3)}
}
func (s *Server) mtu() int {
	if s.cfg.MTU <= 0 {
		return defaultShapeMTU
	}
	return s.cfg.MTU
}
func (s *Server) Serve() error {
	if s.cfg.PacketDeviceFactory == nil {
		go s.tunLoop()
	}
	go s.recvIKE()
	go s.recvNATT()
	select {
	case <-s.done:
		return nil
	case err := <-s.serveErr:
		_ = s.Close()
		return err
	}
}
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.ikeConn.Close()
		s.nattConn.Close()
		s.mu.Lock()
		peers := map[*serverPeer]bool{}
		for _, p := range s.byCookie {
			peers[p] = true
		}
		controls := make([]*serverControl, 0, len(s.byTunnel))
		for _, t := range s.byTunnel {
			controls = append(controls, t)
		}
		s.mu.Unlock()
		for _, t := range controls {
			s.removeControl(t, net.ErrClosed)
		}
		for p := range peers {
			s.removePeer(p, net.ErrClosed)
		}
	})
	return nil
}
func (s *Server) recvIKE() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.ikeConn.ReadFromUDP(buf)
		if err != nil {
			s.readFailed("recvIKE", err)
			return
		}
		s.dispatchIKE(append([]byte(nil), buf[:n]...), addr, false)
	}
}
func (s *Server) recvNATT() {
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes, froms := make([]int, 16), make([]*net.UDPAddr, 16)
	for {
		n, err := s.nattConn.ReadBatch(bufs, sizes, froms)
		for i := range n {
			pkt := append([]byte(nil), bufs[i][:sizes[i]]...)
			addr := froms[i]
			if msg, ok := isIKE(pkt); ok {
				s.dispatchIKE(msg, addr, true)
			} else if p := s.peerBySPI(pkt); p != nil {
				p.handleESP(pkt, addr)
			}
		}
		if err != nil {
			s.readFailed("recvNATT", err)
			return
		}
	}
}
func (s *Server) dispatchIKE(msg []byte, addr *net.UDPAddr, natt bool) {
	cookie, ok := ikev1.InitiatorCookie(msg)
	if !ok {
		return
	}
	if !ikev1.IsInitialMainMode(msg) {
		s.mu.Lock()
		known := s.byCookie[cookie] != nil
		s.mu.Unlock()
		if !known {
			return
		}
	}
	p := s.peerFor(cookie, addr, natt)
	if p == nil {
		return
	}
	p.mu.Lock()
	old := p.ikeNATT && !natt
	p.mu.Unlock()
	if old {
		return
	}
	p.ike.HandleInboundAuthenticated(msg, func() { p.noteIKEAddr(addr, natt) })
}
func (s *Server) peerFor(cookie [8]byte, addr *net.UDPAddr, natt bool) *serverPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	default:
	}
	if p := s.byCookie[cookie]; p != nil {
		return p
	}
	if len(s.byCookie) >= maxCryptoPeers {
		s.logger.Warnf("l2tp: crypto-peer capacity exhausted")
		return nil
	}
	if s.gate == nil {
		s.gate = dataplane.NewGate(dataplane.AdmissionConfig{})
	}
	if r := s.gate.Admit(addr); r != dataplane.Admitted {
		s.logger.Warnf("l2tp: refusing new peer %s: %v", addr, r)
		return nil
	}
	// A new cookie is a new crypto peer. Never guess renewal from a shared
	// NAT endpoint; registered outbound renewals already have explicit aliases.
	p := &serverPeer{srv: s, cookie: cookie, addr: cloneUDPAddr(addr), nattAddr: cloneUDPAddr(addr), ikeNATT: natt, done: make(chan struct{}), controls: map[*serverControl]bool{}}
	localPort := uint16(defaultIKEPort)
	if s.ikeConn != nil {
		localPort = uint16(s.ikeConn.LocalAddr().(*net.UDPAddr).Port)
	}
	p.ike = ikev1.NewSession(ikev1.Config{Role: ikev1.Responder, ManageLifetime: true, PSK: s.cfg.PSK, LocalIP: s.publicIP(), PeerIP: addr.IP, LocalPort: localPort, PeerPort: uint16(addr.Port), Send: p.sendIKE, Handler: p, Logger: s.logger})
	s.byCookie[cookie] = p
	go p.monitor()
	s.logger.Printf("l2tp: new peer %s (cookie %x)", addr, cookie)
	return p
}
func (s *Server) publicIP() net.IP {
	if s.cfg.PublicIP != nil {
		return s.cfg.PublicIP
	}
	if s.ikeConn != nil {
		if la, ok := s.ikeConn.LocalAddr().(*net.UDPAddr); ok && !la.IP.IsUnspecified() {
			return la.IP
		}
	}
	return nil
}
func (s *Server) peerBySPI(pkt []byte) *serverPeer {
	if len(pkt) < 4 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bySPI[binary.BigEndian.Uint32(pkt)]
}
func (s *Server) mapSPI(spi uint32, p *serverPeer) {
	s.mu.Lock()
	if s.byCookie[p.cookie] == p {
		s.bySPI[spi] = p
	}
	s.mu.Unlock()
}
func (s *Server) peerByIP(ip net.IP) *serverCall {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byIP[binary.BigEndian.Uint32(v4)]
}
func (s *Server) removePeer(p *serverPeer, err error) { s.removePeerIfIdle(p, err, false) }
func (s *Server) removePeerIfIdle(p *serverPeer, err error, onlyIdle bool) {
	s.mu.Lock()
	if s.byCookie[p.cookie] != p {
		s.mu.Unlock()
		return
	}
	p.mu.Lock()
	if p.closed || onlyIdle && len(p.controls) != 0 {
		p.mu.Unlock()
		s.mu.Unlock()
		return
	}
	p.closed = true
	for c, owner := range s.byCookie {
		if owner == p {
			delete(s.byCookie, c)
		}
	}
	for spi, owner := range s.bySPI {
		if owner == p {
			delete(s.bySPI, spi)
		}
	}
	controls := make([]*serverControl, 0, len(p.controls))
	for t := range p.controls {
		controls = append(controls, t)
	}
	addr := cloneUDPAddr(p.addr)
	if p.done != nil {
		close(p.done)
	}
	p.mu.Unlock()
	s.mu.Unlock()
	p.releaseAdmission()
	if p.ike != nil {
		go p.ike.Close()
	}
	for _, t := range controls {
		t.detachCarrier(p, err)
	}
	s.logger.Printf("l2tp: crypto peer %s cookie=%x gone: %v", addr, p.cookie, err)
}
func (s *Server) auth(user string) (string, bool) { pw, ok := s.cfg.Users[user]; return pw, ok }
func (s *Server) tunLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			s.readFailed("tunLoop", err)
			return
		}
		if c := s.peerByIP(ipv4Dst(buf[:n])); c != nil {
			if err := c.sendIP(buf[:n], func(reply []byte) { _, _ = s.tun.Write(reply) }); err != nil {
				c.beginDrain(err)
			}
		}
	}
}

// serverPeer owns cryptographic state only. User identity belongs to each PPP
// call; peerIdentity below is the authenticated IKE endpoint identity, not user.
type serverPeer struct {
	srv                   *Server
	cookie                [8]byte
	ike                   *ikev1.Session
	mu                    sync.Mutex
	addr, nattAddr        *net.UDPAddr
	ikeNATT, closed, used bool
	sa                    *esp.SA
	sas                   map[uint32]timedSA
	inSPI                 uint32
	identity              peerIdentity
	controls              map[*serverControl]bool
	done                  chan struct{}
	admissionOnce         sync.Once
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}
func (p *serverPeer) noteIKEAddr(addr *net.UDPAddr, natt bool) {
	p.mu.Lock()
	if p.ikeNATT && !natt {
		p.mu.Unlock()
		return
	}
	old := p.addr
	if p.ikeNATT {
		old = p.nattAddr
	}
	changed := old.Port != addr.Port || !old.IP.Equal(addr.IP) || natt != p.ikeNATT
	if natt {
		p.nattAddr = cloneUDPAddr(addr)
		p.ikeNATT = true
	} else {
		p.addr = cloneUDPAddr(addr)
	}
	p.mu.Unlock()
	if changed {
		p.srv.logger.Printf("l2tp: authenticated IKE endpoint %s -> %s (cookie=%x NAT-T=%v)", old, addr, p.cookie, natt)
	}
}
func (p *serverPeer) noteAddr(addr *net.UDPAddr) {
	p.mu.Lock()
	p.nattAddr = cloneUDPAddr(addr)
	p.mu.Unlock()
}
func (p *serverPeer) sendIKE(msg []byte, _ bool) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	natt := p.ikeNATT
	to := cloneUDPAddr(p.addr)
	if natt {
		to = cloneUDPAddr(p.nattAddr)
	}
	p.mu.Unlock()
	conn, packet := p.srv.ikeConn, msg
	if natt {
		conn, packet = p.srv.nattConn, markIKE(msg)
	}
	n, err := conn.WriteToUDP(packet, to)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("l2tp: IKE UDP send %s -> %s (NAT-T=%v): %w", conn.LocalAddr(), to, natt, err)
	}
	return nil
}
func (p *serverPeer) handleESP(pkt []byte, addr *net.UDPAddr) {
	if len(pkt) < 4 {
		return
	}
	spi := binary.BigEndian.Uint32(pkt)
	p.mu.Lock()
	entry, ok := p.sas[spi]
	closed := p.closed
	active := entry.sa == p.sa
	identity := p.identity
	p.mu.Unlock()
	if closed || !ok || !time.Now().Before(entry.expires) {
		return
	}
	inner, nh, err := entry.sa.Decapsulate(pkt)
	if err != nil || nh != ipProtoUDP {
		return
	}
	l2, ok := unwrapUDP(inner, entry.transport)
	if !ok {
		return
	}
	if active && entry.sa.NeedsRekey() && p.ike != nil {
		p.ike.RequestRekey()
	}
	// Validation and replay checks precede endpoint binding and L2TP allocation.
	p.noteAddr(addr)
	p.srv.routeL2TP(p, spi, identity, entry.transport, binary.BigEndian.Uint16(inner), binary.BigEndian.Uint16(inner[2:]), l2)
}
func (p *serverPeer) Established(r ikev1.Result) {
	p.releaseAdmission()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	identity, err := makePeerIdentity(r.PeerID, r.Transport, p.addr.IP)
	if err != nil {
		p.mu.Unlock()
		go p.srv.removePeer(p, err)
		return
	}
	if p.identity.valid && p.identity != identity {
		p.mu.Unlock()
		go p.srv.removePeer(p, errors.New("l2tp: IKE renewal changed client identity"))
		return
	}
	p.identity = identity
	p.sa = newESPSA(r)
	p.inSPI = r.InSPI
	if p.sas == nil {
		p.sas = map[uint32]timedSA{}
	}
	p.sas[r.InSPI] = timedSA{sa: p.sa, expires: time.Now().Add(r.Lifetime), transport: r.Transport}
	p.mu.Unlock()
	p.srv.mapSPI(r.InSPI, p)
	// Only renew carriers of tunnels already bound to this crypto peer. A new
	// peer with the same identity may be a concurrent login, not a renewal.
	p.mu.Lock()
	controls := make([]*serverControl, 0, len(p.controls))
	for t := range p.controls {
		controls = append(controls, t)
	}
	p.mu.Unlock()
	for _, t := range controls {
		t.addCarrier(p, r.InSPI, r.Transport, false)
	}
	p.srv.logger.Printf("l2tp: IPsec SA established cookie=%x (spi in=%#x out=%#x rekey=%v)", p.cookie, r.InSPI, r.OutSPI, r.Rekey)
}
func (p *serverPeer) Failed(err error) { p.srv.removePeer(p, err) }
func (p *serverPeer) releaseAdmission() {
	p.admissionOnce.Do(func() {
		if p.srv.gate != nil {
			p.srv.gate.Done()
		}
	})
}
func (p *serverPeer) monitor() {
	setup := time.NewTimer(time.Minute)
	defer setup.Stop()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-setup.C:
			p.mu.Lock()
			used := p.used
			p.mu.Unlock()
			if !used {
				p.srv.removePeer(p, errors.New("l2tp: IPsec peer has no L2TP tunnel after setup deadline"))
				return
			}
		case <-ticker.C:
			p.pruneSAs()
			p.mu.Lock()
			idle := p.used && len(p.controls) == 0
			p.mu.Unlock()
			if idle {
				p.srv.removePeerIfIdle(p, errors.New("l2tp: crypto peer has no remaining control tunnels"), true)
			}
		}
	}
}
func (p *serverPeer) RegisterIKE(cookie [8]byte) {
	p.srv.mu.Lock()
	if p.srv.byCookie[p.cookie] == p {
		p.srv.byCookie[cookie] = p
	}
	p.srv.mu.Unlock()
}
func (p *serverPeer) UnregisterIKE(cookie [8]byte) {
	p.srv.mu.Lock()
	if cookie != p.cookie && p.srv.byCookie[cookie] == p {
		delete(p.srv.byCookie, cookie)
	}
	p.srv.mu.Unlock()
}
func (p *serverPeer) DeleteESP(spi uint32) {
	p.srv.mu.Lock()
	p.mu.Lock()
	current := p.sa != nil && p.sa.SPIOut == spi
	for in, e := range p.sas {
		if e.sa.SPIOut == spi {
			delete(p.sas, in)
			if p.srv.bySPI[in] == p {
				delete(p.srv.bySPI, in)
			}
		}
	}
	controls := make([]*serverControl, 0, len(p.controls))
	for t := range p.controls {
		controls = append(controls, t)
	}
	p.mu.Unlock()
	p.srv.mu.Unlock()
	for _, t := range controls {
		t.detachUnavailableCarrier(p)
	}
	if current {
		p.srv.removePeer(p, errors.New("l2tp: peer deleted active ESP SA"))
	}
}
func (p *serverPeer) pruneSAs() {
	p.srv.mu.Lock()
	p.mu.Lock()
	for spi, e := range p.sas {
		if !time.Now().Before(e.expires) {
			delete(p.sas, spi)
			if p.srv.bySPI[spi] == p {
				delete(p.srv.bySPI, spi)
			}
		}
	}
	controls := make([]*serverControl, 0, len(p.controls))
	for t := range p.controls {
		controls = append(controls, t)
	}
	p.mu.Unlock()
	p.srv.mu.Unlock()
	for _, t := range controls {
		t.detachUnavailableCarrier(p)
	}
}
func (s *Server) KickUserSessions(user string) int {
	s.mu.Lock()
	var calls []*serverCall
	for _, c := range s.byIP {
		c.mu.Lock()
		match := c.username == user && !c.closed && !c.draining
		c.mu.Unlock()
		if match {
			calls = append(calls, c)
		}
	}
	s.mu.Unlock()
	for _, c := range calls {
		c.beginDrain(errors.New("l2tp: user disconnected"))
	}
	return len(calls)
}
func (s *Server) readFailed(op string, err error) {
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.serveErr <- fmt.Errorf("l2tp: %s: %w", op, err):
	default:
	}
}
func ipv4Dst(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}

type timedSA struct {
	transport ikev1.TransportPolicy
	sa        *esp.SA
	expires   time.Time
}
