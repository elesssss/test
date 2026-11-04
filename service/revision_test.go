package service

import (
	"encoding/json"
	"testing"

	"github.com/alireza0/s-ui/database/model"
)

func TestRevisionDetectsSameSecondSaves(t *testing.T) {
	db := clientTestDB(t)
	s := &ConfigService{}
	previous, err := s.Revision()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := db.Create(&model.Changes{DateTime: 123, Actor: "test", Key: "config", Action: "set", Obj: json.RawMessage(`{}`)}).Error; err != nil {
			t.Fatal(err)
		}
		changed, err := s.CheckChanges(previous)
		if err != nil || !changed {
			t.Fatalf("same-second change hidden: changed=%v err=%v", changed, err)
		}
		revision, err := s.Revision()
		if err != nil || revision == previous {
			t.Fatal("revision did not advance")
		}
		previous = revision
	}
	if changed, err := s.CheckChanges(previous); err != nil || changed {
		t.Fatal("unchanged revision requested refresh")
	}
	if changed, err := s.CheckChanges("9999999999"); err != nil || !changed {
		t.Fatal("legacy browser time was treated as a current revision")
	}
}
