package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateReplacementRestoresOldBinary(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	old, next := filepath.Join(dir, "sui"), filepath.Join(stage, "sui")
	if err := os.WriteFile(old, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(next, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	files := []*updateReplacement{{source: next, destination: old, mode: 0755}}
	if err := installUpdateFiles(stage, files); err != nil {
		t.Fatal(err)
	}
	if err := restoreUpdateFiles(files); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(old)
	if err != nil || string(data) != "old" {
		t.Fatal("failed scheduling could not restore old binary")
	}
}

func TestUpdateScriptKeepsUnitAndBacksUpSidecars(t *testing.T) {
	script := updateRestartScript("/opt/s-ui/sui", "/opt/s-ui/.update-test", "/srv/custom/s-ui.db", []*updateReplacement{{destination: "/opt/s-ui/sui", backup: "/opt/s-ui/.update-test/old", existed: true}})
	for _, required := range []string{"systemctl stop s-ui", "/srv/custom/s-ui.db-wal", "/srv/custom/s-ui.db-shm", "db_saved=1", "trap rollback", " migrate", "systemctl is-active"} {
		if !strings.Contains(script, required) {
			t.Errorf("missing update protection: %s", required)
		}
	}
	if strings.Contains(script, "/etc/systemd/system/") || strings.Contains(script, "daemon-reload") {
		t.Fatal("panel update modifies the custom unit")
	}
	if latestReleaseURL != "https://api.github.com/repos/bryet/s-ui/releases/latest" || releaseDownloadURL != "https://github.com/bryet/s-ui/releases/download/" {
		t.Fatal("update targets upstream binary")
	}
}
