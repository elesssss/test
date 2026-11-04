package service

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/util/common"
)

const (
	releaseDownloadURL = "https://github.com/bryet/s-ui/releases/download/"
	// The unit install.sh writes. Upgrading in place only makes sense for the
	// installation that unit runs; anything else was set up by hand.
	systemdUnit = "s-ui.service"
	// Well above the size of a release archive, so a broken or hostile answer
	// cannot fill the disk.
	maxArchiveSize = 512 << 20
)

// Only a plain dotted tag reaches a URL or the restart script.
var releaseTagPattern = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*$`)

var upgrading atomic.Bool

// updateMethod tells a container, the systemd service install.sh sets up, and
// everything else apart.
func updateMethod() string {
	if runtime.GOOS != "linux" {
		return UpdateManual
	}
	// Only the image runtimes: an LXC or nspawn guest sets $container too, and
	// install.sh inside one runs under systemd like anywhere else.
	switch os.Getenv("container") {
	case "docker", "podman":
		return UpdateDocker
	}
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return UpdateDocker
		}
	}
	if runsAsSystemdUnit() {
		if _, err := exec.LookPath("systemd-run"); err == nil {
			return UpdateSystemd
		}
	}
	return UpdateManual
}

// runsAsSystemdUnit reports whether this process lives in s-ui.service's
// cgroup, which is the one the restart below acts on.
func runsAsSystemdUnit() bool {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasSuffix(scanner.Text(), "/"+systemdUnit) {
			return true
		}
	}
	return false
}

// releaseArch names the archive built for this binary, as release.yml does.
func releaseArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64", "386", "s390x":
		return runtime.GOARCH, nil
	case "arm":
		goarm := "7"
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				// Go 1.22 may append ",softfloat" or ",hardfloat".
				if s.Key == "GOARM" && s.Value != "" {
					goarm = s.Value[:1]
				}
			}
		}
		return "armv" + goarm, nil
	}
	return "", common.NewErrorf("no release is built for %s", runtime.GOARCH)
}

// Upgrade installs the latest release over this one and has systemd restart
// the panel on it. The files are fetched, checked and swapped in while the
// panel keeps running, so a failure on the way leaves it as it was; only the
// stop, migration and start run outside it, in a transient unit that outlives
// the service it restarts.
func (s *UpdateService) Upgrade() error {
	info := s.CheckUpdate()
	if info.Method != UpdateSystemd {
		return common.NewError("this installation cannot be updated from the panel")
	}
	if !info.HasUpdate {
		return common.NewError("already on the latest version")
	}
	if !releaseTagPattern.MatchString(info.tag) {
		return common.NewError("unexpected release tag: ", info.tag)
	}
	if !upgrading.CompareAndSwap(false, true) {
		return common.NewError("an update is already running")
	}
	err := s.upgradeTo(info.tag)
	if err != nil {
		upgrading.Store(false)
	}
	return err
}

func (s *UpdateService) upgradeTo(tag string) error {
	arch, err := releaseArch()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	// It is quoted into the restart script.
	if strings.ContainsAny(exe, "'\n") {
		return common.NewError("unsupported install path: ", exe)
	}

	// Next to the binary, so the final rename stays on one filesystem.
	stage, err := os.MkdirTemp(filepath.Dir(exe), ".update-")
	if err != nil {
		return err
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = os.RemoveAll(stage)
		}
	}()

	archiveName := "s-ui-linux-" + arch + ".tar.gz"
	base := releaseDownloadURL + tag + "/"
	sums, err := downloadText(base + "SHA256SUMS")
	if err != nil {
		return common.NewError("unable to fetch checksums: ", err)
	}
	expected := checksumFor(sums, archiveName)
	if expected == "" {
		return common.NewError("no checksum published for ", archiveName)
	}
	archive := filepath.Join(stage, archiveName)
	actual, err := downloadFile(base+archiveName, archive)
	if err != nil {
		return common.NewError("unable to download ", archiveName, ": ", err)
	}
	if actual != expected {
		return common.NewError("checksum mismatch for ", archiveName)
	}
	logger.Info("downloaded and verified ", archiveName, " ", tag)

	if err := extractRelease(archive, stage); err != nil {
		return common.NewError("unable to extract ", archiveName, ": ", err)
	}
	newBin := filepath.Join(stage, "sui")
	if err := checkBinary(newBin, strings.TrimPrefix(tag, "v")); err != nil {
		return err
	}

	// Preserve the unit and its Environment/ExecStart overrides. Replace only
	// executable payloads, retaining backups until scheduling and migration finish.
	replacements := []*updateReplacement{{source: newBin, destination: exe, mode: 0755}}
	for _, name := range []string{"libcronet.so"} {
		source := filepath.Join(stage, name)
		if _, e := os.Stat(source); e == nil {
			replacements = append(replacements, &updateReplacement{source: source, destination: filepath.Join(filepath.Dir(exe), name), mode: 0755})
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	if err = installUpdateFiles(stage, replacements); err != nil {
		keepStage = true
		return fmt.Errorf("update staging failed; recovery files retained in %s: %w", stage, err)
	}
	if err = scheduleUpdateRestart(exe, stage, replacements); err != nil {
		if restoreErr := restoreUpdateFiles(replacements); restoreErr != nil {
			keepStage = true
			return errors.Join(err, fmt.Errorf("update rollback failed; backups retained in %s: %w", stage, restoreErr))
		}
		return err
	}
	keepStage = true // the transient unit owns cleanup after successful startup
	return nil
}

func downloadText(url string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", common.NewErrorf("unexpected status code %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(body), err
}

// downloadFile saves url to dst and returns its SHA-256.
func downloadFile(url, dst string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", common.NewErrorf("unexpected status code %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArchiveSize+1))
	if err != nil {
		return "", err
	}
	if n > maxArchiveSize {
		return "", common.NewError("archive is too large")
	}
	return hex.EncodeToString(h.Sum(nil)), f.Close()
}

// checksumFor finds name in a sha256sum listing, with or without the * a
// binary entry carries.
func checksumFor(sums, name string) string {
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			return strings.ToLower(fields[0])
		}
	}
	return ""
}

// extractRelease reads executable payloads only. Unit/menu files are not
// replaced from the panel, so local service configuration stays intact.
func extractRelease(archive, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	wanted := map[string]os.FileMode{"sui": 0755, "libcronet.so": 0755}
	found := make(map[string]bool)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dir, name := path.Split(strings.TrimPrefix(path.Clean(hdr.Name), "./"))
		mode, ok := wanted[name]
		if dir != "s-ui/" || !ok {
			continue
		}
		if found[name] {
			return common.NewError("duplicate release entry: ", name)
		}
		out, err := os.OpenFile(filepath.Join(dst, name), os.O_CREATE|os.O_WRONLY|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, io.LimitReader(tr, maxArchiveSize))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		found[name] = true
	}
	if !found["sui"] {
		return common.NewError("no s-ui/sui in the archive")
	}
	return nil
}

// checkBinary runs the new binary once, so one that cannot start on this host
// never replaces the one that can.
func checkBinary(bin, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
	if err != nil {
		return common.NewError("the new binary does not run on this server: ", err)
	}
	if !strings.Contains(string(out), version) {
		return common.NewError("the new binary reports an unexpected version")
	}
	return nil
}
