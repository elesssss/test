package service

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alireza0/s-ui/config"
	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/util/common"
)

// The update unit outlives s-ui.service. Unit configuration and its environment
// are kept intact; only the executable payloads participate in the update.
func scheduleUpdateRestart(exe, stage string, files []*updateReplacement) error {
	dbPath, err := filepath.Abs(config.GetDBPath())
	if err != nil {
		return err
	}
	args := []string{
		"--no-block", "--collect",
		"--unit", "s-ui-update-" + time.Now().Format("20060102150405"),
		"--description", "s-ui panel update",
		"--setenv", "SUI_DB_FOLDER=" + filepath.Dir(dbPath),
		"/bin/sh", "-c", updateRestartScript(exe, stage, dbPath, files),
	}
	out, err := exec.Command("systemd-run", args...).CombinedOutput()
	if err != nil {
		return common.NewError("unable to schedule restart: ", err, " ", strings.TrimSpace(string(out)))
	}
	logger.Info("update scheduled; rollback backups retained in ", stage)
	return nil
}

func updateRestartScript(exe, stage, dbPath string, files []*updateReplacement) string {
	var rollback strings.Builder
	for i := len(files) - 1; i >= 0; i-- {
		file := files[i]
		if file.existed {
			tmp := file.destination + ".rollback"
			fmt.Fprintf(&rollback, "cp -p -- %s %s && mv -f -- %s %s || failed=1\n", shellQuote(file.backup), shellQuote(tmp), shellQuote(tmp), shellQuote(file.destination))
		} else {
			fmt.Fprintf(&rollback, "rm -f -- %s || failed=1\n", shellQuote(file.destination))
		}
	}
	// Copy a quiescent SQLite database and every sidecar. A failed migration's
	// WAL must never be replayed against the restored database.
	var saveDB, restoreDB strings.Builder
	for i, suffix := range []string{"", "-wal", "-shm"} {
		source := dbPath + suffix
		backup := filepath.Join(stage, fmt.Sprintf("database-%d", i))
		fmt.Fprintf(&saveDB, "if [ -e %s ]; then cp -p -- %s %s; fi\n", shellQuote(source), shellQuote(source), shellQuote(backup))
		fmt.Fprintf(&restoreDB, "if [ -e %s ]; then cp -p -- %s %s || failed=1; else rm -f -- %s || failed=1; fi\n", shellQuote(backup), shellQuote(backup), shellQuote(source), shellQuote(source))
	}
	return "set -eu\ndb_saved=0\nrollback() {\ntrap - EXIT HUP INT TERM\nset +e\nfailed=0\n" +
		"if ! systemctl stop s-ui || systemctl is-active --quiet s-ui; then printf 'Cannot stop s-ui safely; backups retained\\n' >&2; exit 1; fi\n" + rollback.String() +
		"if [ \"$db_saved\" = 1 ]; then\n" + restoreDB.String() + "fi\n" +
		"if [ \"$failed\" = 0 ]; then systemctl start s-ui || failed=1; fi\n" +
		"printf 'Update failed; rollback status=%s; backups retained at %s\\n' \"$failed\" " + shellQuote(stage) + " >&2\nexit 1\n}\n" +
		"trap rollback EXIT HUP INT TERM\nsleep 2\nsystemctl stop s-ui\nif systemctl is-active --quiet s-ui; then exit 1; fi\n" + saveDB.String() +
		"db_saved=1\n" + shellQuote(exe) + " migrate\nsystemctl start s-ui\nsleep 2\nsystemctl is-active --quiet s-ui\n" +
		"trap - EXIT HUP INT TERM\nrm -rf -- " + shellQuote(stage) + "\n"
}
