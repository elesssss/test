package util

import (
	"net/url"
	"testing"
)

// Gecko arrived with sing-box 1.14; only salamander was read from a link, so a
// gecko node imported with no obfuscation at all. #1328
func TestHysteria2LinkObfsTypes(t *testing.T) {
	for _, obfsType := range []string{"salamander", "gecko"} {
		t.Run(obfsType, func(t *testing.T) {
			out, _, err := GetOutbound("hysteria2://pass@example.com:443/?sni=example.com&obfs="+obfsType+"&obfs-password=secret#node", 0)
			if err != nil {
				t.Fatal(err)
			}
			obfs, _ := (*out)["obfs"].(map[string]interface{})
			if obfs["type"] != obfsType || obfs["password"] != "secret" {
				t.Fatalf("obfs = %v, want %s with the link's password", (*out)["obfs"], obfsType)
			}
		})
	}
}

func TestGeckoPacketSizesRoundTrip(t *testing.T) {
	inbound := inboundFor(t, "hysteria2", map[string]interface{}{
		"obfs": map[string]interface{}{"type": "gecko", "password": "test-password", "min_packet_size": 600, "max_packet_size": 1100},
	})
	links := LinkGenerator(clientConfigFor(t, "hysteria2", map[string]interface{}{"password": "test-auth"}), inbound, "example.test", "")
	if len(links) != 1 {
		t.Fatalf("links = %v", links)
	}
	u, err := url.Parse(links[0])
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("obfs-min-packet-size") != "600" || u.Query().Get("obfs-max-packet-size") != "1100" {
		t.Fatalf("missing Gecko URI parameters: %s", links[0])
	}
	out, _, err := GetOutbound(links[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	obfs, _ := (*out)["obfs"].(map[string]interface{})
	if obfs["min_packet_size"] != float64(600) || obfs["max_packet_size"] != float64(1100) {
		t.Fatalf("packet sizes lost: %v", obfs)
	}
	for _, typ := range []string{"salamander", "gecko"} {
		out, _, err := GetOutbound("hy2://test@example.test:443?obfs="+typ+"&obfs-min-packet-size=invalid&obfs-max-packet-size=-1", 0)
		if err != nil {
			t.Fatal(err)
		}
		obfs, _ := (*out)["obfs"].(map[string]interface{})
		if _, ok := obfs["min_packet_size"]; ok {
			t.Fatalf("invalid packet size retained: %v", obfs)
		}
		if _, ok := obfs["max_packet_size"]; ok {
			t.Fatalf("invalid packet size retained: %v", obfs)
		}
	}
}
