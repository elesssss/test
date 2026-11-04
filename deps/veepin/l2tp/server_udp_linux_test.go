//go:build linux

package l2tp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/wanan9999/veepin/dataplane"
	"golang.org/x/sys/unix"
)

func TestServerWildcardUsesIPv4AndRepliesOnObservedSocket(t *testing.T) {
	ike, err := listenServerUDP(net.IPv4zero, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ike.Close()
	natt, err := listenServerUDP(net.IPv4zero, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer natt.Close()
	for _, socket := range []*net.UDPConn{ike, natt} {
		raw, err := socket.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var domain int
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			domain, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
		}); err != nil {
			t.Fatal(err)
		}
		if sockErr != nil || domain != unix.AF_INET {
			t.Fatalf("IPv4 wildcard listener is not AF_INET: domain=%d err=%v", domain, sockErr)
		}
	}
	// Read through PacketConn so the response exercises the actual PKTINFO
	// path, rather than sending only over a socket bound to loopback.
	for _, socket := range []*net.UDPConn{ike, natt} {
		packetConn := dataplane.NewPacketConn(socket)
		server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: socket.LocalAddr().(*net.UDPAddr).Port}
		client, err := net.DialUDP("udp4", nil, server)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		client.SetDeadline(time.Now().Add(2 * time.Second))
		packetConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		request := []byte{0, 0, 0, 0, 1, 2, 3, 4}
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 256)
		var n int
		var peer *net.UDPAddr
		if socket == natt {
			// Production receives floated IKE through ReadBatch, which must
			// preserve the same IPv4 PKTINFO as the plain IKE read path.
			sizes, froms := make([]int, 1), make([]*net.UDPAddr, 1)
			var count int
			count, err = packetConn.ReadBatch([][]byte{buf}, sizes, froms)
			if err == nil && count != 1 {
				t.Fatalf("expected one NAT-T datagram, got %d", count)
			}
			n, peer = sizes[0], froms[0]
		} else {
			n, peer, err = packetConn.ReadFromUDP(buf)
		}
		if err != nil || !bytes.Equal(buf[:n], request) {
			t.Fatalf("read request: %v", err)
		}
		if _, err := packetConn.WriteToUDP(request, peer); err != nil {
			t.Fatal(err)
		}
		n, err = client.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], request) {
			t.Fatalf("pinned reply did not reach connected IPv4 client: %v", err)
		}
	}
}
