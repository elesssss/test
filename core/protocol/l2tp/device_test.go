//go:build linux && with_gvisor

package l2tp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	gs "github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

type echoRouter struct {
	adapter.Router
	events       chan adapter.InboundContext
	eventsByUser map[string]chan adapter.InboundContext
}

func (r *echoRouter) record(metadata adapter.InboundContext) {
	if r.eventsByUser != nil {
		r.eventsByUser[metadata.User] <- metadata
		return
	}
	r.events <- metadata
}

func (r *echoRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.record(metadata)
	go func() {
		_, err := io.Copy(conn, conn)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}
func (r *echoRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.record(metadata)
	go func() {
		defer conn.Close()
		for {
			packet := buf.NewPacket()
			destination, err := conn.ReadPacket(packet)
			if err != nil {
				packet.Release()
				if onClose != nil {
					onClose(err)
				}
				return
			}
			if err = conn.WritePacket(packet, destination); err != nil {
				if onClose != nil {
					onClose(err)
				}
				return
			}
		}
	}()
}

func TestSessionStackTCPUDPAndIdentity(t *testing.T) {
	// Identical inner addresses must retain their own identity both after reuse
	// and while two stacks on one inbound are carrying traffic concurrently.
	for _, mode := range []string{"sequential-reuse", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			router := &echoRouter{eventsByUser: map[string]chan adapter.InboundContext{"alice": make(chan adapter.InboundContext, 8), "bob": make(chan adapter.InboundContext, 8)}}
			in := &Inbound{Adapter: inbound.NewAdapter(Type, "vpn"), ctx: ctx, router: router, logger: log.NewNOPFactory().Logger()}
			for _, user := range []string{"alice", "bob"} {
				t.Run(user, func(t *testing.T) {
					if mode == "concurrent" {
						t.Parallel()
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					mtu := uint16(1400)
					if user == "bob" {
						mtu = 576
					}
					d, err := newSessionDevice(ctx, in, user, netip.MustParseAddr("10.20.0.2"), netip.MustParsePrefix("10.20.0.1/24"), mtu)
					if err != nil {
						t.Fatal(err)
					}
					defer d.Close()
					if d.endpoint.MTU() != uint32(mtu) {
						t.Fatal("negotiated MRU was not applied to link endpoint")
					}
					s := gs.New(gs.Options{NetworkProtocols: []gs.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []gs.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
					defer s.Close()
					ep := channel.New(128, 1400, "")
					defer ep.Close()
					if e := s.CreateNIC(1, ep); e != nil {
						t.Fatal(e)
					}
					if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 20, 0, 2}).WithPrefix()}, gs.AddressProperties{}); e != nil {
						t.Fatal(e)
					}
					s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
					go func() {
						for {
							p := ep.ReadContext(ctx)
							if p == nil {
								return
							}
							v := p.ToView()
							_, _ = d.Write(v.AsSlice())
							v.Release()
							p.DecRef()
						}
					}()
					go func() {
						b := make([]byte, 65535)
						for {
							n, e := d.Read(b)
							if e != nil {
								return
							}
							p := gs.NewPacketBuffer(gs.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b[:n]...))})
							ep.InjectInbound(ipv4.ProtocolNumber, p)
							p.DecRef()
						}
					}()
					destination := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}), Port: 8080}
					tcpConn, err := gonet.DialContextTCP(ctx, s, destination, ipv4.ProtocolNumber)
					if err != nil {
						t.Fatal(err)
					}
					defer tcpConn.Close()
					udpConn, err := gonet.DialUDP(s, nil, &destination, ipv4.ProtocolNumber)
					if err != nil {
						t.Fatal(err)
					}
					defer udpConn.Close()
					for _, conn := range []net.Conn{tcpConn, udpConn} {
						payload := []byte(user)
						if conn == tcpConn {
							payload = bytes.Repeat(payload, 1024)
						}
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						if _, err = conn.Write(payload); err != nil {
							t.Fatal(err)
						}
						reply := make([]byte, len(payload))
						if _, err = io.ReadFull(conn, reply); err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(reply, payload) {
							t.Fatal("echo payload changed")
						}
						select {
						case m := <-router.eventsByUser[user]:
							if m.User != user || m.Inbound != "vpn" || m.InboundType != Type {
								t.Fatalf("lost identity: %+v", m)
							}
						case <-ctx.Done():
							t.Fatal("routing was bypassed")
						}
					}
					d.Close()
					if _, err = d.Write(make([]byte, 20)); err == nil {
						t.Fatal("closed device accepts packets")
					}
				})
			}
		})
	}
}

func TestOptionsRejectInvalidConfiguration(t *testing.T) {
	for _, bad := range []Options{
		{PublicIP: "example.com", PSK: "test"},
		{PublicIP: "192.0.2.1", PSK: "test", Pool: "0.0.0.0/0"},
		{PublicIP: "192.0.2.1", PSK: "test", ListenPort: 4500},
		{PublicIP: "192.0.2.1", PSK: "test", Users: []User{{Name: "a", Password: "x"}, {Name: "a", Password: "y"}}},
	} {
		if bad.validate() == nil {
			t.Fatalf("accepted invalid options: %+v", bad)
		}
	}
}
