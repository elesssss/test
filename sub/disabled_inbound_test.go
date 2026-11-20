package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
)

func TestSubsSkipDisabledInbounds(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "disabled.db")); err != nil {
		t.Fatal(err)
	}
	db := database.GetDB()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	inbounds := []model.Inbound{
		{Type: "socks", Tag: "on", Options: json.RawMessage(`{}`), Addrs: json.RawMessage(`[]`), OutJson: json.RawMessage(`{"type":"socks","tag":"on","server":"192.0.2.1","server_port":1080}`)},
		{Type: "socks", Tag: "off", Options: json.RawMessage(`{"enable":false}`), Addrs: json.RawMessage(`[]`), OutJson: json.RawMessage(`{"type":"socks","tag":"off","server":"192.0.2.2","server_port":1080}`)},
	}
	if err := db.Create(&inbounds).Error; err != nil {
		t.Fatal(err)
	}
	original := json.RawMessage(`[
		{"type":"local","remark":"on","uri":"socks5://192.0.2.1:1080#on"},
		{"type":"local","remark":"off","uri":"socks5://192.0.2.2:1080#off"},
		{"type":"external","remark":"off","uri":"socks5://192.0.2.3:1080#external"}
	]`)
	client := model.Client{
		Name: "disabled-test", Enable: true, Config: json.RawMessage(`{"socks":{}}`),
		Inbounds: json.RawMessage(fmt.Sprintf("[%d,%d]", inbounds[0].Id, inbounds[1].Id)), Links: original,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true, false} {
		if err := inbounds[1].SetEnabled(enabled); err != nil {
			t.Fatal(err)
		}
		if err := db.Model(&inbounds[1]).Update("options", inbounds[1].Options).Error; err != nil {
			t.Fatal(err)
		}
		for _, happ := range []bool{false, true} {
			var result *string
			var err error
			service := &SubService{}
			if happ {
				result, _, err = service.getSubs(client.Name, happLinks)
			} else {
				result, _, err = service.GetSubs(client.Name)
			}
			if err != nil {
				t.Fatal(err)
			}
			body := *result
			if encode, _ := service.GetSubEncode(); encode {
				decoded, err := base64.StdEncoding.DecodeString(body)
				if err != nil {
					t.Fatal(err)
				}
				body = string(decoded)
			}
			if strings.Contains(body, "192.0.2.2") != enabled || !strings.Contains(body, "192.0.2.3") {
				t.Fatalf("enabled=%v happ=%v: %s", enabled, happ, body)
			}
		}
		_, selected, err := (&JsonService{}).getData(client.Name)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if enabled {
			want++
		}
		if len(selected) != want {
			t.Fatalf("JSON/Clash selected %d inbounds, want %d", len(selected), want)
		}
		for _, format := range []string{"json", "clash"} {
			var result *string
			if format == "json" {
				result, _, err = (&JsonService{}).GetJson(client.Name, format)
			} else {
				result, _, err = (&ClashService{}).GetClash(client.Name)
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(*result, "192.0.2.2") != enabled || !strings.Contains(*result, "192.0.2.3") {
				t.Fatalf("%s enabled=%v: %s", format, enabled, *result)
			}
		}
	}
	var stored model.Client
	if err := db.First(&stored, client.Id).Error; err != nil {
		t.Fatal(err)
	}
	if string(stored.Links) != string(original) {
		t.Fatal("subscription rendering mutated stored links")
	}
	// Invalid switch metadata fails closed instead of advertising the inbound.
	if err := db.Model(&inbounds[1]).Update("options", json.RawMessage(`{"enable":"invalid"}`)).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := dropDisabledLinks(&client); err == nil {
		t.Fatal("raw subscription ignored invalid enable metadata")
	}
	if _, _, err := (&JsonService{}).getData(client.Name); err == nil {
		t.Fatal("JSON/Clash ignored invalid enable metadata")
	}
}
