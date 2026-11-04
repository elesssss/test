package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sync"

	"github.com/sagernet/sing-box/option"
)

// PolicyUpdate is prepared while the previous policy serves traffic. The
// caller serializes lifecycle changes, commits storage, then publishes. Abort
// releases every prepared resource if validation or the database commit fails.
type PolicyUpdate struct {
	box       *Box
	runtime   *policyRuntime
	options   option.Options
	impact    policyImpact
	once      sync.Once
	commitErr error
}

func (u *PolicyUpdate) Abort() {
	u.once.Do(func() {
		u.commitErr = net.ErrClosed
		if u.runtime != nil {
			u.runtime.close()
		}
	})
}
func (u *PolicyUpdate) Commit() error {
	u.once.Do(func() {
		if u.runtime != nil {
			u.commitErr = u.box.policy.publish(u.runtime.generation, u.impact)
			if u.commitErr != nil {
				return
			}
		}
		u.box.policy.mu.Lock()
		if u.box.policy.stopped {
			u.commitErr = net.ErrClosed
		} else {
			u.box.applied = u.options
		}
		u.box.policy.mu.Unlock()
	})
	return u.commitErr
}

func (c *Core) PreparePolicy(raw []byte) (*PolicyUpdate, error) {
	b, err := c.running()
	if err != nil {
		return nil, err
	}
	var options option.Options
	if err := options.UnmarshalJSONContext(c.ctx, raw); err != nil {
		return nil, err
	}
	generation := b.policy.acquire()
	if generation == nil {
		return nil, net.ErrClosed
	}
	defer generation.release()
	current := generation.runtime
	b.policy.mu.Lock()
	applied := b.applied
	b.policy.mu.Unlock()
	if !sameOptions(policyBase(applied), policyBase(options)) {
		return nil, fmt.Errorf("changes to global settings require stopping the core before saving; current dial-up sessions are unchanged")
	}
	update := &PolicyUpdate{box: b, options: options}
	if sameOptions(applied.Route, options.Route) && sameOptions(applied.DNS, options.DNS) && sameOptions(applied.Outbounds, options.Outbounds) && sameOptions(applied.HTTPClients, options.HTTPClients) {
		return update, nil
	}
	// These services hold native manager references outside the routing entry.
	// Refuse an incomplete reload instead of claiming it applied or redialling.
	if len(options.Endpoints) != 0 || len(options.Services) != 0 || len(options.CertificateProviders) != 0 || (options.Experimental != nil && (options.Experimental.ClashAPI != nil || options.Experimental.V2RayAPI != nil)) {
		return nil, fmt.Errorf("policy hot reload is not supported with endpoints, core services or certificate providers; stop the core before saving")
	}
	if options.NTP != nil && options.NTP.Enabled {
		return nil, fmt.Errorf("policy hot reload is not supported with NTP enabled; stop the core before saving")
	}
	if options.Experimental != nil && options.Experimental.CacheFile != nil && options.Experimental.CacheFile.Enabled {
		return nil, fmt.Errorf("policy hot reload is not supported with persistent core cache enabled; stop the core before saving")
	}
	// Native inbound dialers (Reality/ShadowTLS detours, TLS DNS resolvers)
	// capture managers at construction and are not routed by policyRouter.
	// Reject incomplete reloads rather than leaving them on retired resources.
	for _, inbound := range applied.Inbounds {
		if err := validateInboundPolicyReferences(c.ctx, inbound); err != nil {
			return nil, err
		}
	}
	for _, inbound := range options.Inbounds {
		if err := validateInboundPolicyReferences(c.ctx, inbound); err != nil {
			return nil, err
		}
	}
	for _, inbound := range b.inbound.Inbounds() {
		if inbound.Type() == "tun" {
			return nil, fmt.Errorf("policy hot reload is not supported with TUN inbounds; stop the core before saving")
		}
	}
	p, err := b.preparePolicy(options)
	if err != nil {
		return nil, fmt.Errorf("prepare policy (current configuration remains running): %w", err)
	}
	update.runtime = p
	if !sameOptions(applied.Route, options.Route) || !sameOptions(applied.HTTPClients, options.HTTPClients) {
		// A route rule may depend on sniffed data, DNS answers or a remote
		// rule-set. Re-evaluating stored metadata would invent another router.
		update.impact.all = true
	} else {
		changed := changedOutboundTags(applied.Outbounds, options.Outbounds)
		if previousDefault := current.outbound.Default(); previousDefault != nil && previousDefault.Tag() != p.outbound.Default().Tag() {
			changed[previousDefault.Tag()] = true
		}
		// Closing a changed detour also invalidates selectors and other users of
		// it, even when their visible outbound tag itself did not change.
		for more := true; more; {
			more = false
			for _, manager := range []*policyRuntime{current, p} {
				for _, outbound := range manager.outbound.Outbounds() {
					if changed[outbound.Tag()] {
						continue
					}
					for _, dependency := range outbound.Dependencies() {
						if changed[dependency] {
							changed[outbound.Tag()] = true
							more = true
							break
						}
					}
				}
			}
		}
		update.impact.tags = changed
	}
	return update, nil
}

// validateInboundPolicyReferences detects native dialers that bypass the
// stable policy entry. Keep such configurations running, but require an
// explicit core stop before replacing the managers they captured.
func validateInboundPolicyReferences(ctx context.Context, inbound option.Inbound) error {
	raw, err := inbound.MarshalJSONContext(ctx)
	if err != nil {
		return err
	}
	var fields map[string]any
	if err = json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	// The top-level listen detour references another inbound, not an outbound
	// manager. Only nested handshake/dialer detours are policy references.
	delete(fields, "detour")
	var captured func(any) bool
	captured = func(value any) bool {
		switch value := value.(type) {
		case map[string]any:
			for key, field := range value {
				if key == "detour" {
					if tag, ok := field.(string); ok && tag != "" {
						return true
					}
				}
				if key == "domain_resolver" || key == "certificate_provider" {
					if field != nil {
						return true
					}
				}
				if captured(field) {
					return true
				}
			}
		case []any:
			for _, field := range value {
				if captured(field) {
					return true
				}
			}
		}
		return false
	}
	if captured(fields) {
		return fmt.Errorf("policy hot reload is not supported with native inbound policy references on %q; stop the core before saving", inbound.Tag)
	}
	return nil
}

func policyBase(o option.Options) option.Options {
	o.RawMessage, o.CommentsSet = nil, nil
	o.DNS, o.Route, o.Outbounds, o.HTTPClients = nil, nil, nil, nil
	o.Inbounds, o.Endpoints, o.Services = nil, nil, nil
	return o
}

func sameOptions(a, b any) bool {
	// Protocol Options fields are json:"-" and use context-aware marshalers.
	// Compare decoded values, never encoding/json's incomplete representation.
	return reflect.DeepEqual(a, b)
}

func changedOutboundTags(before, after []option.Outbound) map[string]bool {
	previous := make(map[string]option.Outbound, len(before))
	changed := make(map[string]bool)
	for i, outbound := range before {
		tag := outbound.Tag
		if tag == "" {
			tag = fmt.Sprint(i)
		}
		previous[tag] = outbound
	}
	for i, outbound := range after {
		tag := outbound.Tag
		if tag == "" {
			tag = fmt.Sprint(i)
		}
		old, found := previous[tag]
		if !found || !sameOptions(old, outbound) {
			changed[tag] = true
		}
		delete(previous, tag)
	}
	for tag := range previous {
		changed[tag] = true
	}
	return changed
}
