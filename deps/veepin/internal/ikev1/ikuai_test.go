package ikev1

import (
	"bytes"
	"testing"
	"time"
)

// SA body from an iKuai 3.7.14 Main Mode request. Only public proposal
// attributes are retained: no endpoint, cookie, identity or credential.
// AES-128-CBC / SHA-256 / MODP-3072 / PSK, seconds lifetime encoded as TV zero.
const ikuai3714IKE = "00000001000000010000002c01010001000000240101000080010007800e0080800200048004000f80030001800b0001800c0000"

func TestIKuai3714Offer(t *testing.T) {
	s := NewSession(Config{Role: Responder, ManageLifetime: true, IKELifetime: time.Hour})
	defer s.Close()
	p, selected, err := s.selectIKEOffer(wireHex(t, ikuai3714IKE))
	if err != nil {
		t.Fatal(err)
	}
	if p.keyBits != 128 || p.hash != hashSHA2256 || p.group != 15 || p.auth != authPSK || p.lifeSeconds != 3600 {
		t.Fatalf("unexpected selected suite: %+v", p)
	}
	if !bytes.Equal(buildSelectedSA(protoISAKMP, nil, selected), wireHex(t, ikuai3714IKE)) {
		t.Fatal("compatibility changed the wire attributes authenticated by IKE")
	}
}

func TestIKuai3714MainQuickModeAndESP(t *testing.T) {
	// Only phase one was captured from the router. Quick Mode uses the existing
	// synthetic AES-128/SHA-1 fixture; it is not a captured iKuai ESP proposal.
	runAES128HandshakeWithIKE(t, false, wireHex(t, ikuai3714IKE), groupMODP3072, hashSHA2256, wireHex(t, tunnelForgeESP))
}

func TestIKuai3714RejectsWrongPSK(t *testing.T) {
	runAES128HandshakeWithIKE(t, true, wireHex(t, ikuai3714IKE), groupMODP3072, hashSHA2256, wireHex(t, tunnelForgeESP))
}

func TestIKuaiZeroLifetimeCompatibilityIsScoped(t *testing.T) {
	_, _, transforms, err := parseSingleProposalSA(wireHex(t, ikuai3714IKE))
	if err != nil {
		t.Fatal(err)
	}
	attrs := transforms[0].attrs
	if _, ok := ikePropFromAttrs(attrs); ok {
		t.Fatal("strict proposal parser accepted zero lifetime")
	}
	for _, cfg := range []Config{
		{Role: Responder}, // The compatibility path requires managed expiry.
		{Role: Initiator, ManageLifetime: true},
		{Role: Responder, ManageLifetime: true, Mode: ModeAggressive},
		{Role: Responder, ManageLifetime: true, Phase2: Phase2RemoteAccess},
		{Role: Responder, ManageLifetime: true, XAuth: &XAuthConfig{}},
	} {
		s := NewSession(cfg)
		if _, ok := s.ikeOfferProposal(attrs); ok {
			t.Errorf("zero lifetime accepted for unrelated profile: %+v", cfg)
		}
		s.Close()
	}
	for _, duration := range []time.Duration{0, 90 * time.Second, 2 * time.Hour} {
		s := NewSession(Config{Role: Responder, ManageLifetime: true, IKELifetime: duration})
		p, ok := s.ikeOfferProposal(attrs)
		if !ok || p.lifeSeconds != lifetimeSeconds(duration) {
			t.Errorf("local lifetime %v not applied: %+v, ok=%v", duration, p, ok)
		}
		s.Close()
	}
}

func TestIKuaiZeroLifetimeDoesNotAcceptMalformedOrOtherSuites(t *testing.T) {
	_, _, transforms, err := parseSingleProposalSA(wireHex(t, ikuai3714IKE))
	if err != nil {
		t.Fatal(err)
	}
	s := NewSession(Config{Role: Responder, ManageLifetime: true})
	defer s.Close()
	base := transforms[0].attrs
	for _, tc := range []struct {
		name string
		edit func([]attr) []attr
	}{
		{"duplicate encryption", func(a []attr) []attr { return append(a, basicAttr(attrEncryption, encrAES)) }},
		{"duplicate seconds", func(a []attr) []attr { return append(a, basicAttr(attrLifeType, 1), basicAttr(attrLifeDuration, 0)) }},
		{"orphan duration", func(a []attr) []attr { return append(a, basicAttr(attrLifeDuration, 0)) }},
		{"zero volume", func(a []attr) []attr { return append(a, basicAttr(attrLifeType, 2), basicAttr(attrLifeDuration, 0)) }},
		{"unknown attribute", func(a []attr) []attr { return append(a, basicAttr(999, 1)) }},
		{"missing unit", func(a []attr) []attr { return append(a[:5], a[6:]...) }},
		{"empty duration", func(a []attr) []attr { a[6] = varAttr(attrLifeDuration, nil); return a }},
		{"oversized duration", func(a []attr) []attr { a[6] = varAttr(attrLifeDuration, make([]byte, 5)); return a }},
		{"SHA1 suite", func(a []attr) []attr { a[2] = basicAttr(attrHash, hashSHA); return a }},
		{"DH14 suite", func(a []attr) []attr { a[3] = basicAttr(attrGroup, groupMODP2048); return a }},
		{"DH2 suite", func(a []attr) []attr { a[3] = basicAttr(attrGroup, groupMODP1024); return a }},
		{"XAuth suite", func(a []attr) []attr { a[4] = basicAttr(attrAuthMethod, authXAuthInitPSK); return a }},
		{"3DES suite", func(a []attr) []attr { a[0] = basicAttr(attrEncryption, 5); return a }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := tc.edit(append([]attr(nil), base...))
			if _, ok := s.ikeOfferProposal(attrs); ok {
				t.Fatal("compatibility accepted malformed or unrelated proposal")
			}
		})
	}
	for _, duration := range []attr{basicAttr(attrLifeDuration, 0), varAttr(attrLifeDuration, []byte{0, 0, 0, 0})} {
		attrs := append([]attr(nil), base...)
		attrs[6] = duration
		if _, ok := s.ikeOfferProposal(attrs); !ok {
			t.Fatal("valid zero seconds encoding rejected")
		}
	}
}

func TestIKuaiDH15PolicyAndRenewal(t *testing.T) {
	p := ikeProposal{encr: encrAES, keyBits: 256, hash: hashSHA2256, group: groupMODP3072, auth: authPSK, lifeSeconds: 3600}
	for _, cfg := range []Config{{Role: Initiator}, {Role: Responder, Phase2: Phase2RemoteAccess}} {
		s := NewSession(cfg)
		if s.supportedIKE(p) {
			t.Errorf("ordinary profile gained DH15: %+v", cfg)
		}
		s.Close()
	}
	s := NewSession(Config{Role: Responder, ManageLifetime: true})
	defer s.Close()
	if !s.supportedIKE(p) {
		t.Fatal("L2TP responder rejected DH15 with normal lifetime")
	}
	s.prop = p
	child := s.newRenewalLocked(Initiator, [8]byte{})
	if child == nil || !child.supportedIKE(p) {
		t.Fatal("IKE renewal cannot reuse the negotiated DH15 suite")
	}
	var sent []byte
	child.cfg.Send = func(b []byte, _ bool) error { sent = bytes.Clone(b); return nil }
	if err := child.sendMM1(); err != nil {
		t.Fatal(err)
	}
	_, first, rest, err := parseHeader(sent)
	if err != nil {
		t.Fatal(err)
	}
	payloads, _, err := parsePayloads(first, rest)
	if err != nil {
		t.Fatal(err)
	}
	sa, ok := findPayload(payloads, payloadSA)
	if !ok {
		t.Fatal("renewal has no SA")
	}
	_, _, transforms, err := parseSingleProposalSA(sa.body)
	if err != nil || len(transforms) != 1 {
		t.Fatalf("invalid renewal offer: %v", err)
	}
	proposal, ok := ikePropFromAttrs(transforms[0].attrs)
	if !ok || proposal.group != groupMODP3072 || proposal.lifeSeconds == 0 {
		t.Fatalf("renewal did not offer finite DH15 policy: %+v", proposal)
	}
	for _, proposal := range defaultIKEProposals(authPSK) {
		if proposal.group != groupMODP2048 {
			t.Fatal("default initiator policy changed")
		}
	}
}
