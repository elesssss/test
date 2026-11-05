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
	"github.com/wanan9999/veepin/internal/mschap"
	"github.com/wanan9999/veepin/internal/ppp"
)

// One authenticated PPP call has one IP, MRU and packet device, independently
// of other calls in the control tunnel or on the same IPsec transport.
type serverCall struct {
	control                                 *serverControl
	id                                      uint16
	mu                                      sync.Mutex
	ppp                                     *ppp.ServerSession
	username                                string
	address                                 net.IP
	mtu                                     uint16
	ready, closed, draining, creatingDevice bool
	device                                  io.ReadWriteCloser
	shaper                                  *dataplane.Shaper
	done                                    chan struct{}
	drainTimer                              *time.Timer
	dataSeen, sourceWarned, writeWarned     bool
}

func (t *serverControl) CallUp(id uint16) {
	s := t.srv
	s.mu.Lock()
	t.mu.Lock()
	if t.closed || t.draining || t.calls[id] != nil {
		t.mu.Unlock()
		s.mu.Unlock()
		return
	}
	if s.callCount >= maxServerCalls {
		t.mu.Unlock()
		s.mu.Unlock()
		t.tunnel.CloseCall(id, errors.New("l2tp: server call capacity exhausted"))
		return
	}
	address, err := s.pool.Allocate()
	if err != nil {
		t.mu.Unlock()
		s.mu.Unlock()
		t.tunnel.CloseCall(id, err)
		return
	}
	call := &serverCall{control: t, id: id, address: address, done: make(chan struct{})}
	call.ppp = ppp.NewServer(ppp.ServerConfig{ClientIP: address, ServerIP: s.gateway, DNS: s.cfg.DNS, Auth: s.auth}, callTransport{t.tunnel, id}, serverCallPPP{call})
	t.calls[id] = call
	s.callCount++
	s.byIP[binary.BigEndian.Uint32(address.To4())] = call
	t.mu.Unlock()
	s.mu.Unlock()
	s.logger.Printf("l2tp: L2TP session up tunnel=%d session=%d assigning %s", t.tunnel.LocalTunnelID(), id, address)
	go call.monitorSetup()
	call.ppp.Start()
}
func (t *serverControl) CallData(id uint16, frame []byte) {
	t.mu.Lock()
	call := t.calls[id]
	t.mu.Unlock()
	if call != nil {
		call.dataFrame(frame)
	}
}
func (t *serverControl) CallClosed(id uint16, err error) {
	t.mu.Lock()
	call := t.calls[id]
	t.mu.Unlock()
	if call != nil {
		call.drain(err)
	}
}
func (c *serverCall) monitorSetup() {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	select {
	case <-c.done:
		return
	case <-timer.C:
		c.mu.Lock()
		ready := c.ready || c.draining
		c.mu.Unlock()
		if !ready {
			c.beginDrain(errors.New("l2tp: PPP call setup timed out"))
		}
	}
}
func (c *serverCall) beginDrain(err error) {
	if !c.drain(err) {
		return
	}
	c.control.tunnel.CloseCall(c.id, err)
}
func (c *serverCall) drain(err error) bool {
	c.mu.Lock()
	if c.closed || c.draining {
		c.mu.Unlock()
		return false
	}
	c.draining = true
	c.ready = false
	device, ps := c.device, c.ppp
	c.device = nil
	c.drainTimer = time.AfterFunc(31*time.Second, func() { c.control.srv.removeCall(c, err) })
	c.mu.Unlock()
	if device != nil {
		_ = device.Close()
	}
	if ps != nil {
		go ps.Close()
	}
	return true
}
func (c *serverCall) stopData() { c.drain(errors.New("l2tp: control tunnel closing")) }
func (s *Server) removeCall(c *serverCall, err error) {
	t := c.control
	s.mu.Lock()
	t.mu.Lock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		t.mu.Unlock()
		s.mu.Unlock()
		return
	}
	c.closed, c.ready = true, false
	close(c.done)
	if c.drainTimer != nil {
		c.drainTimer.Stop()
	}
	device, ps, address, user := c.device, c.ppp, c.address, c.username
	c.device = nil
	if t.calls[c.id] == c {
		delete(t.calls, c.id)
		s.callCount--
	}
	key := binary.BigEndian.Uint32(address.To4())
	if s.byIP[key] == c {
		delete(s.byIP, key)
	}
	c.mu.Unlock()
	t.mu.Unlock()
	s.mu.Unlock()
	s.pool.Release(address)
	if device != nil {
		_ = device.Close()
	}
	if ps != nil {
		go ps.Close()
	}
	s.logger.Printf("l2tp: PPP call tunnel=%d session=%d user=%q address=%s gone: %v", t.tunnel.LocalTunnelID(), c.id, user, address, err)
}
func (c *serverCall) dataFrame(frame []byte) {
	if ip, ok := ppp.IsIP(frame); ok {
		c.mu.Lock()
		ready := c.ready && !c.closed && !c.draining
		device, address := c.device, append(net.IP(nil), c.address...)
		c.mu.Unlock()
		if !ready || len(ip) < 20 || ip[0]>>4 != 4 {
			return
		}
		if !net.IP(ip[12:16]).Equal(address) {
			c.mu.Lock()
			warn := !c.sourceWarned
			c.sourceWarned = true
			c.mu.Unlock()
			if warn {
				c.control.srv.logger.Warnf("l2tp: tunnel=%d session=%d dropping IPv4 source %s; assigned=%s (source-NAT required)", c.control.tunnel.LocalTunnelID(), c.id, net.IP(ip[12:16]), address)
			}
			return
		}
		var n int
		var err error
		if device != nil {
			n, err = device.Write(ip)
		} else if c.control.srv.tun != nil {
			n, err = c.control.srv.tun.Write(ip)
		} else {
			return
		}
		if err == nil && n != len(ip) {
			err = io.ErrShortWrite
		}
		c.mu.Lock()
		warn, first := err != nil && !c.writeWarned, err == nil && !c.dataSeen
		c.writeWarned = c.writeWarned || err != nil
		c.dataSeen = c.dataSeen || err == nil
		c.mu.Unlock()
		if warn {
			c.control.srv.logger.Warnf("l2tp: call %d packet device write: %v", c.id, err)
		}
		if first {
			c.control.srv.logger.Printf("l2tp: first tunnel IPv4 packet admitted tunnel=%d session=%d source=%s protocol=%d", c.control.tunnel.LocalTunnelID(), c.id, address, ip[9])
		}
		return
	}
	c.mu.Lock()
	ps, closed := c.ppp, c.closed || c.draining
	c.mu.Unlock()
	if ps != nil && !closed {
		ps.Receive(frame)
	}
}
func (c *serverCall) sendIP(packet []byte, feedback func([]byte)) error {
	c.mu.Lock()
	ready := c.ready && !c.closed && !c.draining
	address, mtu := append(net.IP(nil), c.address...), int(c.mtu)
	c.mu.Unlock()
	if !ready || !ipv4Dst(packet).Equal(address) {
		return nil
	}
	// Existing PMTU/fragment logic uses a call-specific sender, not another
	// call's IDs or MRU. Padding is also bounded by this call's negotiated MRU.
	pad := 0
	if c.control.srv.cfg.Shape > 0 {
		c.mu.Lock()
		if c.shaper == nil {
			c.shaper = dataplane.NewShaper(dataplane.ShapeConfig{Bytes: c.control.srv.cfg.Shape})
		}
		pad = c.shaper.Target(packet, min(mtu, c.control.srv.mtu()))
		c.mu.Unlock()
	}
	return sendIPv4Through(callTransport{c.control.tunnel, c.id}, packet, mtu, pad, feedback)
}
func (c *serverCall) deviceLoop(device io.ReadWriteCloser) {
	buf := make([]byte, 65535)
	for {
		n, err := device.Read(buf)
		if err != nil {
			c.mu.Lock()
			current := c.device == device && !c.closed && !c.draining
			c.mu.Unlock()
			if current {
				c.beginDrain(err)
			}
			return
		}
		c.mu.Lock()
		current := c.device == device && c.ready && !c.closed && !c.draining
		c.mu.Unlock()
		if !current {
			return
		}
		if err := c.sendIP(buf[:n], func(reply []byte) { _, _ = device.Write(reply) }); err != nil {
			c.beginDrain(err)
			return
		}
	}
}

type serverCallPPP struct{ call *serverCall }

func (h serverCallPPP) Authenticated(user, password string, nt [mschap.NTResponseLen]byte) {
	c := h.call
	c.mu.Lock()
	defer c.mu.Unlock()
	// PPP validates credentials before this callback. Never rebind an already
	// authenticated call to another account on a duplicate CHAP exchange.
	if c.username == "" && !c.closed && !c.draining {
		c.username = user
	}
}
func (h serverCallPPP) NetworkUp(mtu uint16) {
	c := h.call
	c.mu.Lock()
	if c.closed || c.draining || c.ready || c.creatingDevice || c.username == "" {
		c.mu.Unlock()
		return
	}
	c.creatingDevice = true
	user, address := c.username, append(net.IP(nil), c.address...)
	c.mu.Unlock()
	var device io.ReadWriteCloser
	var err error
	if factory := c.control.srv.cfg.PacketDeviceFactory; factory != nil {
		device, err = factory(user, address, mtu)
		if err == nil && device == nil {
			err = errors.New("l2tp: nil packet device")
		}
	}
	c.mu.Lock()
	c.creatingDevice = false
	if err != nil || c.closed || c.draining {
		c.mu.Unlock()
		if device != nil {
			device.Close()
		}
		if err != nil {
			c.beginDrain(fmt.Errorf("l2tp: packet device: %w", err))
		}
		return
	}
	c.device, c.ready, c.mtu = device, true, mtu
	c.mu.Unlock()
	if device != nil {
		go c.deviceLoop(device)
	}
	c.control.srv.logger.Printf("l2tp: PPP up tunnel=%d session=%d user=%q address=%s", c.control.tunnel.LocalTunnelID(), c.id, user, address)
}
func (h serverCallPPP) NetworkDown() {
	c := h.call
	c.mu.Lock()
	device := c.device
	c.device = nil
	c.ready = false
	c.mu.Unlock()
	if device != nil {
		device.Close()
	}
}
func (h serverCallPPP) Closed(err error) { h.call.beginDrain(err) }

var _ ppp.ServerHandler = serverCallPPP{}
