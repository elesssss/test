//go:build linux && with_gvisor

package l2tp

import (
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (h *sessionHandler) judgeICMP(source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	// The stack uses the echo identifier as a flow selector, not a network port.
	metadata := h.metadata(N.NetworkICMP, M.Socksaddr{Addr: source.Addr()}, M.Socksaddr{Addr: destination.Addr()})
	result := h.inbound.router.PreMatch(metadata, firstPacket)
	switch result.Action {
	case adapter.PreMatchDrop:
		return tun.FlowVerdict{Action: tun.ActionDrop}
	case adapter.PreMatchFlow, adapter.PreMatchBypass:
		port, ok := result.Outbound.(tun.Port)
		if !ok {
			break
		}
		v4, _ := port.PortAddresses()
		// Fixed-address tunnel ports need a shared selector allocator across PPP
		// stacks. Socket-backed ports (direct) can key flows by each user's IP.
		if !v4.Is4() || !v4.IsUnspecified() {
			break
		}
		if result.Destination.IsValid() && !result.Destination.Addr().Is4() {
			break
		}
		// Cache one wrapper per session/outbound so sing-tun can reuse its NAT
		// and detach the return path on device close without touching other users.
		h.icmpMu.Lock()
		if h.icmpPorts == nil {
			h.icmpPorts = make(map[tun.Port]*sessionICMPPort)
		}
		wrapped := h.icmpPorts[port]
		if wrapped == nil {
			wrapped = &sessionICMPPort{Port: port, address: h.address}
			h.icmpPorts[port] = wrapped
		}
		h.icmpMu.Unlock()
		verdict := tun.FlowVerdict{Action: tun.ActionFlow, Port: wrapped, NewTracker: result.NewTracker}
		if result.Destination.IsValid() {
			verdict.Destination = netip.AddrPortFrom(result.Destination.Addr(), destination.Port())
		}
		return verdict
	}
	// ActionAccept (including no ICMP-capable outbound) fabricates an echo reply
	// in gVisor. Fail closed instead: a successful ping must come from the target.
	return tun.FlowVerdict{Action: tun.ActionReject}
}

// sing-tun falls back to its local echo responder if AttachReturn fails. This
// wrapper instead retains an error for WritePackets, keeping that flow on the
// forwarding path and preventing an unreachable target from appearing online.
type sessionICMPPort struct {
	tun.Port
	address   netip.Addr
	mu        sync.RWMutex
	attachErr error
}

func (p *sessionICMPPort) PortAddresses() (netip.Addr, netip.Addr) {
	v4, v6 := p.Port.PortAddresses()
	// A direct ping port reports 0.0.0.0 because its socket chooses an external
	// source. Keep the assigned PPP address on the internal return path instead:
	// gVisor's writeback must not see an unspecified destination, and separate
	// per-user dispatchers must not allocate identical return tuples.
	if v4.IsUnspecified() {
		v4 = p.address
	}
	return v4, v6
}

func (p *sessionICMPPort) AttachReturn(path tun.Return) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attachErr = p.Port.AttachReturn(path)
	return nil
}
func (p *sessionICMPPort) WritePackets(packets [][]byte) error {
	p.mu.RLock()
	err := p.attachErr
	p.mu.RUnlock()
	if err != nil {
		return err
	}
	return p.Port.WritePackets(packets)
}
