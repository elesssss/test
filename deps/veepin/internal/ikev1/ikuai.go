package ikev1

// supportedIKEDHGroup leaves ordinary initiators and remote-access profiles on
// their existing policy. L2TP responders can select iKuai's group 15; an IKE
// renewal may reuse that negotiated group without changing the default offers.
func (s *Session) supportedIKEDHGroup(group uint16) bool {
	return group == groupMODP2048 || (group == groupMODP3072 &&
		s.cfg.Phase2 == Phase2L2TP && (s.cfg.Role == Responder || s.renewalRoot != nil))
}

// ikeOfferProposal keeps strict parsing as the default. iKuai 3.7.14 sends a
// zero seconds lifetime with its AES-128/SHA-256/MODP-3072/PSK offer. Interpret
// only that Main Mode L2TP responder case using the finite local IKE lifetime.
// The returned suite is for timers; the original transform is still echoed on
// the wire and the original SA body is still used by HASH_I/HASH_R.
func (s *Session) ikeOfferProposal(attrs []attr) (ikeProposal, bool) {
	if p, ok := ikePropFromAttrs(attrs); ok {
		return p, true
	}
	if !s.cfg.ManageLifetime || s.cfg.Role != Responder || s.cfg.Mode != ModeMain || s.cfg.Phase2 != Phase2L2TP || s.cfg.XAuth != nil {
		return ikeProposal{}, false
	}

	normalized := append([]attr(nil), attrs...)
	changed := false
	for i, a := range attrs {
		if a.typ != attrLifeDuration || i == 0 || attrs[i-1].typ != attrLifeType {
			continue
		}
		unit, valid := attrUint16(attrs[i-1])
		if !valid || unit != lifeTypeSeconds || len(a.value) == 0 || len(a.value) > 4 {
			continue
		}
		zero := true
		for _, b := range a.value {
			zero = zero && b == 0
		}
		if zero {
			normalized[i] = varAttr(attrLifeDuration, be32(lifetimeSeconds(s.cfg.IKELifetime)))
			changed = true
		}
	}
	if !changed {
		return ikeProposal{}, false
	}
	// Reuse all structural, duplicate-attribute and lifetime-unit checks. A zero
	// volume lifetime, unsupported attribute or extra duration remains invalid.
	p, ok := ikePropFromAttrs(normalized)
	if !ok || p.encr != encrAES || p.keyBits != 128 || p.hash != hashSHA2256 || p.group != groupMODP3072 || p.auth != authPSK {
		return ikeProposal{}, false
	}
	return p, true
}
