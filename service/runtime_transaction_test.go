package service

import (
	"bytes"
	"errors"
	"testing"

	"github.com/alireza0/s-ui/database/model"
)

func TestRuntimeChangesRestoreAllObjectsOnCommitFailure(t *testing.T) {
	for _, kind := range []string{"inbound", "service", "endpoint"} {
		t.Run(kind, func(t *testing.T) {
			runtime := &inboundTestRuntime{configs: map[string][]byte{"one": []byte(`{"tag":"one","value":"old"}`)}}
			old := bytes.Clone(runtime.configs["one"])
			change := &runtimeObjectChange{kind: kind, tag: "one", before: old, after: []byte(`{"tag":"one","value":"new"}`), add: runtime.AddInbound, remove: runtime.RemoveInbound}
			failure := errors.New("synthetic commit failure")
			if err := applyRuntimeChanges([]*runtimeObjectChange{change}, func() error { return failure }); !errors.Is(err, failure) {
				t.Fatalf("commit cause lost: %v", err)
			}
			if !bytes.Equal(runtime.configs["one"], old) {
				t.Fatal("old runtime was not restored")
			}
		})
	}
}

func TestRuntimeChangesRestoreAuthenticationAfterFailedCommit(t *testing.T) {
	old, next := []byte(`{"users":["disabled"]}`), []byte(`{"users":["enabled"]}`)
	current := bytes.Clone(old)
	closed := false
	change := &runtimeObjectChange{tag: "vpn", before: old, after: next, update: func(config []byte) (bool, error) { current = bytes.Clone(config); return true, nil }, afterCommit: func() { closed = true }}
	failure := errors.New("audit/commit failed")
	if err := applyRuntimeChanges([]*runtimeObjectChange{change}, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if !bytes.Equal(current, old) || closed {
		t.Fatal("uncommitted authentication persisted or sessions closed")
	}
}

func TestRuntimeChangesRemoveCandidatesBeforeRestoringRenamedObject(t *testing.T) {
	old := []byte(`{"tag":"z-old"}`)
	runtime := &inboundTestRuntime{configs: map[string][]byte{"z-old": old}}
	changes := []*runtimeObjectChange{
		{kind: "inbound", tag: "a-new", after: []byte(`{"tag":"a-new"}`), add: runtime.AddInbound, remove: runtime.RemoveInbound},
		{kind: "inbound", tag: "z-old", before: old, add: runtime.AddInbound, remove: runtime.RemoveInbound},
	}
	if err := applyRuntimeChanges(changes, func() error { return errors.New("fail") }); err == nil {
		t.Fatal("failure hidden")
	}
	if len(runtime.configs) != 1 || !bytes.Equal(runtime.configs["z-old"], old) {
		t.Fatal("rename rollback left candidate installed")
	}
}

func TestStaleZeroTrafficEditDoesNotResetUsage(t *testing.T) {
	db := clientTestDB(t)
	c := createClient(t, db, &model.Client{Name: "alice", Enable: true, Up: 100, Down: 200, TotalUp: 30})
	stale := &model.Client{Id: c.Id, Name: c.Name, Up: 0, Down: 0}
	(&ClientService{}).preserveServerOwnedFields(db, stale)
	if stale.Up != 100 || stale.Down != 200 || stale.TotalUp != 30 {
		t.Fatal("zero form values reset latest traffic")
	}
}
