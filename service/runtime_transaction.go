package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"gorm.io/gorm"
)

// Runtime changes and their database commit form one serialized operation.
// Failed activation/commit restores every affected object, in reverse order.
// Callers hold lifecycleMu; snapshots are taken before database mutation.
type runtimeObjectChange struct {
	kind, tag      string
	before, after  []byte
	remove         func(string) error
	add            func([]byte) error
	removed, added bool
	updated        bool
	update         func([]byte) (bool, error)
	afterCommit    func()
	afterRestore   func()
}

type runtimeSnapshot map[string][]byte

func (s *ConfigService) snapshotRuntime(db *gorm.DB, object string) (runtimeSnapshot, error) {
	result := runtimeSnapshot{}
	if corePtr == nil || corePtr.GetInstance() == nil {
		return result, nil
	}
	if object == "clients" || object == "tls" {
		inbounds, err := s.InboundService.GetAllConfig(db)
		if err != nil {
			return nil, err
		}
		if err = appendRuntimeConfigs(result, "inbound", inbounds); err != nil {
			return nil, err
		}
	}
	if object == "tls" || object == "services" {
		services, err := s.ServicesService.GetAllConfig(db)
		if err != nil {
			return nil, err
		}
		if err = appendRuntimeConfigs(result, "service", services); err != nil {
			return nil, err
		}
	}
	if object == "endpoints" {
		endpoints, err := s.EndpointService.GetAllConfig(db)
		if err != nil {
			return nil, err
		}
		if err = appendRuntimeConfigs(result, "endpoint", endpoints); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func appendRuntimeConfigs(dst runtimeSnapshot, kind string, configs []json.RawMessage) error {
	for _, config := range configs {
		var ref struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(config, &ref); err != nil {
			return err
		}
		dst[kind+":"+ref.Tag] = bytes.Clone(config)
	}
	return nil
}

func runtimeChanges(before, after runtimeSnapshot) []*runtimeObjectChange {
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	var changes []*runtimeObjectChange
	for _, key := range ordered {
		if bytes.Equal(before[key], after[key]) {
			continue
		}
		kind, tag, _ := strings.Cut(key, ":")
		change := &runtimeObjectChange{kind: kind, tag: tag, before: before[key], after: after[key]}
		if corePtr == nil {
			changes = append(changes, change)
			continue
		}
		switch kind {
		case "inbound":
			change.add = corePtr.AddInbound
			if sameInboundExceptUsers(change.before, change.after) {
				change.update = corePtr.UpdateInboundUsers
				change.afterCommit = func() { closeInactiveInboundUsers(change.tag, change.after) }
				change.afterRestore = func() { closeInactiveInboundUsers(change.tag, change.before) }
			}
			change.remove = func(tag string) error {
				box := corePtr.GetInstance()
				err := corePtr.RemoveInbound(tag)
				if box != nil {
					box.SessionTracker().CloseByInbound(tag)
				}
				return err
			}
		case "service":
			change.add, change.remove = corePtr.AddService, corePtr.RemoveService
		case "endpoint":
			change.add, change.remove = corePtr.AddEndpoint, corePtr.RemoveEndpoint
		}
		changes = append(changes, change)
	}
	return changes
}

func applyRuntimeChanges(changes []*runtimeObjectChange, commit func() error) (err error) {
	committed := false
	defer func() {
		panicValue := recover()
		if committed {
			if panicValue != nil {
				panic(panicValue)
			}
			return
		}
		if panicValue != nil {
			err = fmt.Errorf("runtime change panicked: %v", panicValue)
		}
		if err == nil {
			return
		}
		// Remove every candidate first: renamed/swapped tags must be free
		// before any old object is restored.
		for i := len(changes) - 1; i >= 0; i-- {
			change := changes[i]
			if change.added {
				if e := change.remove(change.tag); e != nil && !errors.Is(e, os.ErrInvalid) {
					err = errors.Join(err, fmt.Errorf("remove uncommitted %s %q: %w", change.kind, change.tag, e))
				}
			}
		}
		for i := len(changes) - 1; i >= 0; i-- {
			change := changes[i]
			if change.updated {
				if _, e := change.update(change.before); e != nil {
					err = errors.Join(err, fmt.Errorf("restore users on %q: %w", change.tag, e))
				} else if change.afterRestore != nil {
					change.afterRestore()
				}
			}
			if change.removed && change.before != nil {
				if e := change.add(change.before); e != nil {
					err = errors.Join(err, fmt.Errorf("restore %s %q: %w", change.kind, change.tag, e))
				}
			}
		}
		if panicValue != nil {
			panic(err)
		}
	}()
	for _, change := range changes {
		if change.update != nil {
			// UpdateUsers may have changed authentication state before reporting
			// an error, so make restoration eligible before invoking it.
			change.updated = true
			handled, e := change.update(change.after)
			if e != nil {
				return e
			}
			change.updated = handled
			if handled {
				continue
			}
		}
		if change.before != nil {
			change.removed = true
			if err = change.remove(change.tag); errors.Is(err, os.ErrInvalid) {
				change.removed = false
			} else if err != nil {
				return err
			}
		}
	}
	for _, change := range changes {
		if change.updated {
			continue
		}
		if change.after != nil {
			if err = change.add(change.after); err != nil {
				return err
			}
			change.added = true
		}
	}
	if err = commit(); err != nil {
		return err
	}
	committed = true
	for _, change := range changes {
		if change.updated && change.afterCommit != nil {
			change.afterCommit()
		}
	}
	return nil
}

func closeInactiveInboundUsers(tag string, raw []byte) {
	var config struct {
		Users []struct {
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"users"`
	}
	if json.Unmarshal(raw, &config) != nil {
		return
	}
	keep := map[string]struct{}{}
	for _, user := range config.Users {
		name := user.Name
		if name == "" {
			name = user.Username
		}
		if name != "" {
			keep[name] = struct{}{}
		}
	}
	if box := corePtr.GetInstance(); box != nil {
		box.SessionTracker().CloseByInboundUsers(tag, keep)
	}
	corePtr.CloseInboundUserSessions(tag, keep)
}

func sameInboundExceptUsers(before, after []byte) bool {
	if before == nil || after == nil {
		return false
	}
	var a, b map[string]json.RawMessage
	if json.Unmarshal(before, &a) != nil || json.Unmarshal(after, &b) != nil {
		return false
	}
	delete(a, "users")
	delete(b, "users")
	aRaw, e1 := json.Marshal(a)
	bRaw, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(aRaw, bRaw)
}
