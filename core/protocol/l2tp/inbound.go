//go:build linux && with_gvisor

package l2tp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	vpn "github.com/wanan9999/veepin/l2tp"
)

type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.Router
	logger   log.ContextLogger
	options  Options
	mu       sync.Mutex
	server   *vpn.Server
	closed   bool
	serveErr error
}

func newInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Inbound, error) {
	return &Inbound{Adapter: inbound.NewAdapter(Type, tag), ctx: ctx, router: router, logger: logger, options: options}, nil
}

func (i *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		i.ctx = scope.Context()
		scope.Add(i.Close)
	}
	if stage != adapter.StartStatePostStart {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return net.ErrClosed
	}
	if i.server != nil || len(i.options.Users) == 0 {
		return nil
	}
	users := make(map[string]string)
	for _, u := range i.options.Users {
		users[u.Name] = u.Password
	}
	pool := netip.MustParsePrefix(i.options.Pool)
	gateway := pool.Addr().Next()
	srv, err := vpn.NewServer(vpn.ServerConfig{
		ListenIP: i.options.Listen, PublicIP: i.options.PublicIP, Port: int(i.options.ListenPort),
		PSK: i.options.PSK, Users: users, Pool: i.options.Pool,
		Logger: slog.New(protocolLogHandler{logger: i.logger}),
		DNS:    []net.IP{net.IP(gateway.AsSlice())},
		PacketDeviceFactory: func(user string, address net.IP, mtu uint16) (vpn.PacketDevice, error) {
			return newSessionDevice(i.ctx, i, user, netip.MustParseAddr(address.String()), netip.PrefixFrom(gateway, pool.Bits()), mtu)
		},
	})
	if err != nil {
		return err
	}
	i.server = srv
	go i.runServer(srv.ListenAndServe, srv.Close)
	i.logger.Info("L2TP/IPsec listening on ", i.options.Listen, ":", i.options.ListenPort, " and UDP/4500")
	return nil
}

func (i *Inbound) Close() error {
	i.mu.Lock()
	i.closed = true
	srv := i.server
	i.server = nil
	i.mu.Unlock()
	if srv != nil {
		return srv.Close()
	}
	return nil
}

func (i *Inbound) KickUserSessions(user string) int {
	i.mu.Lock()
	srv := i.server
	i.mu.Unlock()
	if srv == nil {
		return 0
	}
	return srv.KickUserSessions(user)
}

func (i *Inbound) CloseUserSessions(keep map[string]struct{}) int {
	n := 0
	for _, user := range i.options.Users {
		if _, ok := keep[user.Name]; !ok {
			n += i.KickUserSessions(user.Name)
		}
	}
	return n
}

// One handler and stack per authenticated PPP session prevents address reuse
// from inheriting a previous user's connections or routing identity.
type sessionHandler struct {
	inbound   *Inbound
	user      string
	address   netip.Addr
	icmpMu    sync.Mutex
	icmpPorts map[tun.Port]*sessionICMPPort
}

func (h *sessionHandler) metadata(network string, source, destination M.Socksaddr) adapter.InboundContext {
	return adapter.InboundContext{Inbound: h.inbound.Tag(), InboundType: Type, User: h.user, Network: network, Source: source, Destination: destination}
}

func (h *sessionHandler) JudgeFlow(network uint8, source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	if source.Addr() != h.address {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	// Always enter Route*ConnectionEx with the authenticated User attached.
	// A packet-level bypass would skip the panel's tracking and quota hooks.
	if network == 6 || network == 17 {
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	if network == 1 {
		return h.judgeICMP(source, destination, firstPacket)
	}
	return tun.FlowVerdict{Action: tun.ActionReject}
}

func (h *sessionHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.inbound.router.RouteConnectionEx(log.ContextWithNewID(ctx), conn, h.metadata(N.NetworkTCP, source, destination), onClose)
}

func (h *sessionHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.inbound.router.RoutePacketConnectionEx(log.ContextWithNewID(ctx), conn, h.metadata(N.NetworkUDP, source, destination), onClose)
}

func (h *sessionHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	h.inbound.router.HijackDNSPacket(log.ContextWithNewID(h.inbound.ctx), payload, writer, h.metadata(N.NetworkUDP, source, destination))
}

func newSessionDevice(ctx context.Context, i *Inbound, user string, address netip.Addr, gateway netip.Prefix, mtu uint16) (*packetDevice, error) {
	d := newPacketDevice(ctx, mtu)
	stack, err := tun.NewStack("gvisor", tun.StackOptions{
		Context: d.ctx, Tun: d, TunOptions: tun.Options{MTU: uint32(mtu), Inet4Address: []netip.Prefix{gateway}},
		UDPTimeout: 5 * time.Minute, ICMPTimeout: time.Second,
		Handler: &sessionHandler{inbound: i, user: user, address: address}, Logger: i.logger,
	})
	if err != nil {
		d.Close()
		return nil, err
	}
	d.stack = stack
	if err = stack.Start(); err != nil {
		d.Close()
		return nil, fmt.Errorf("l2tp: start userspace stack: %w", err)
	}
	return d, nil
}

// HealthError lets the panel distinguish a live process from a dead listener.
func (i *Inbound) HealthError() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.serveErr
}

// Keep worker exit handling separate from binding so administrative shutdown
// and unexpected termination have a single, testable state transition.
func (i *Inbound) runServer(serve func() error, closeServer func() error) {
	err := serve()
	i.mu.Lock()
	if !i.closed {
		if err == nil {
			err = fmt.Errorf("l2tp: listener exited unexpectedly")
		}
		i.serveErr = err
	}
	failed := i.serveErr
	i.mu.Unlock()
	if failed != nil {
		i.logger.Error("L2TP listener stopped: ", failed)
		_ = closeServer()
	}
}
