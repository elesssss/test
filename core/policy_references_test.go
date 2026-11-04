package core

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestNativeInboundReferencesRejectPolicyReload(t *testing.T) {
	c := NewCore()
	for _, raw := range []string{
		`{"type":"vless","tag":"reality","tls":{"enabled":true,"reality":{"enabled":true,"handshake":{"server":"example.test","server_port":443,"detour":"proxy"}}}}`,
		`{"type":"shadowtls","tag":"shadow","handshake":{"server":"example.test","server_port":443,"detour":"proxy"}}`,
	} {
		var in option.Inbound
		if err := in.UnmarshalJSONContext(c.GetCtx(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
		if err := validateInboundPolicyReferences(c.GetCtx(), in); err == nil {
			t.Fatal("inbound captured a retired policy manager without a guard")
		}
	}
}
