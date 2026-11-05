package l2tp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wanan9999/veepin/dataplane"
)

// One listener, identical phase-one identities and UDP/1701 selectors. This
// models several accounts on one router, not unrelated clients with unique IDs.
func TestConcurrentUsersSameRouterDisconnectRedialAndRekey(t *testing.T) {
	loopback := net.IPv4(127, 0, 0, 1)
	listen := func() *net.UDPConn {
		t.Helper()
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	pool, gateway, err := dataplane.NewAddrPool("10.20.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ike, natt := listen(), listen()
	devices := make(chan sessionDeviceRecord, 32)
	server := NewServer(ike, natt, nil, ServerConfig{
		PSK: []byte("secret"), Users: map[string]string{"alice": "alice-pass", "bob": "bob-pass", "carol": "carol-pass"}, Pool: pool, Gateway: gateway,
		PacketDeviceFactory: func(user string, ip net.IP, mtu uint16) (io.ReadWriteCloser, error) {
			d := newConcurrentDevice()
			devices <- sessionDeviceRecord{user, bytes.Clone(ip), d}
			return d, nil
		},
	})
	go func() { _ = server.Serve() }()
	t.Cleanup(func() { server.Close() })
	type connection struct {
		client *Client
		tun    *fakeTUN
		config NetConfig
		call   *serverCall
		device *concurrentDevice
	}
	dial := func(user string) *connection {
		t.Helper()
		conn, tun := listen(), newFakeTUN()
		client := NewClient(conn, tun, ClientConfig{ServerIP: loopback, LocalIP: loopback, IKEPort: ike.LocalAddr().(*net.UDPAddr).Port, NATTPort: natt.LocalAddr().(*net.UDPAddr).Port, PSK: []byte("secret"), Username: user, Password: user + "-pass"})
		t.Cleanup(func() { client.Close(); close(tun.in) })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		config, err := client.Handshake(ctx)
		if err != nil {
			t.Fatal(err)
		}
		server.mu.Lock()
		call := server.byIP[binary.BigEndian.Uint32(config.AssignedIP.To4())]
		server.mu.Unlock()
		if call == nil {
			t.Fatal("missing call")
		}
		var record sessionDeviceRecord
		select {
		case record = <-devices:
		case <-ctx.Done():
			t.Fatal("packet device not created")
		}
		if record.user != user || !record.ip.Equal(config.AssignedIP) {
			t.Fatal("user identity crossed calls")
		}
		return &connection{client, tun, config, call, record.device}
	}
	alice, bob, carol := dial("alice"), dial("bob"), dial("carol")
	check := func(c *connection) {
		t.Helper()
		up := makeIPv4(c.config.AssignedIP, gateway)
		c.tun.in <- up
		assertPacket(t, "independent uplink", c.device.out, up)
		down := makeIPv4(gateway, c.config.AssignedIP)
		c.device.in <- down
		assertPacket(t, "independent downlink", c.tun.out, down)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := c.client.Probe(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*connection{alice, bob, carol} {
		check(c)
	}
	server.mu.Lock()
	if len(server.byTunnel) != 3 || len(server.byIP) != 3 {
		t.Fatal("same router accounts merged")
	}
	server.mu.Unlock()
	// A bad account must not tear down already authenticated neighbors.
	badConn, badTUN := listen(), newFakeTUN()
	bad := NewClient(badConn, badTUN, ClientConfig{ServerIP: loopback, LocalIP: loopback, IKEPort: ike.LocalAddr().(*net.UDPAddr).Port, NATTPort: natt.LocalAddr().(*net.UDPAddr).Port, PSK: []byte("secret"), Username: "bob", Password: "wrong"})
	t.Cleanup(func() { bad.Close(); close(badTUN.in) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = bad.Handshake(ctx)
	cancel()
	if err == nil {
		t.Fatal("invalid password admitted")
	}
	check(alice)
	check(carol)
	if n := server.KickUserSessions("bob"); n != 1 {
		t.Fatalf("kicked %d calls", n)
	}
	select {
	case <-bob.device.done:
	default:
		t.Fatal("kicked device retained")
	}
	check(alice)
	check(carol)
	// Redial while the old call and its IP still have teardown tombstones.
	bob2 := dial("bob")
	if bob2.config.AssignedIP.Equal(bob.config.AssignedIP) {
		t.Fatal("draining IP reused")
	}
	check(bob2)
	check(alice)
	check(carol)
	for round := range 4 {
		active := []*connection{alice, bob2, carol}
		oldSPI := make(map[*connection]uint32)
		for _, c := range active {
			c.client.mu.Lock()
			oldSPI[c] = c.client.sa.SPIIn
			c.client.mu.Unlock()
		}
		var wg sync.WaitGroup
		errors := make(chan error, 3)
		for _, c := range []*connection{alice, bob2, carol} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if round%2 == 0 {
					errors <- c.client.ike.Rekey()
				} else {
					errors <- c.client.ike.RenewIKE()
				}
			}()
		}
		wg.Wait()
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range active {
			deadline := time.Now().Add(3 * time.Second)
			for {
				c.client.mu.Lock()
				changed := c.client.sa.SPIIn != oldSPI[c]
				c.client.mu.Unlock()
				if changed {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("renewal round %d stalled", round)
				}
				time.Sleep(time.Millisecond)
			}
		}
		// A HELLO/data exchange on each connection proves the replacement SAs
		// still address the original PPP users; no new factory must be invoked.
		for _, c := range []*connection{alice, bob2, carol} {
			check(c)
		}
	}
	select {
	case r := <-devices:
		t.Fatalf("renewal recreated %s device", r.user)
	default:
	}
	server.mu.Lock()
	calls := []*serverCall{alice.call, bob2.call, carol.call}
	server.mu.Unlock()
	for _, c := range calls {
		c.mu.Lock()
		if !c.ready || c.closed || c.draining {
			t.Fatal(fmt.Sprintf("renewal lost %s", c.username))
		}
		c.mu.Unlock()
	}
}

type sessionDeviceRecord struct {
	user   string
	ip     net.IP
	device *concurrentDevice
}
type concurrentDevice struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func newConcurrentDevice() *concurrentDevice {
	return &concurrentDevice{in: make(chan []byte, 32), out: make(chan []byte, 32), done: make(chan struct{})}
}
func (d *concurrentDevice) Read(b []byte) (int, error) {
	select {
	case <-d.done:
		return 0, net.ErrClosed
	case p := <-d.in:
		return copy(b, p), nil
	}
}
func (d *concurrentDevice) Write(b []byte) (int, error) {
	select {
	case <-d.done:
		return 0, net.ErrClosed
	case d.out <- bytes.Clone(b):
		return len(b), nil
	}
}
func (d *concurrentDevice) Close() error { d.once.Do(func() { close(d.done) }); return nil }
