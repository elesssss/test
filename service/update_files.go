package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type updateReplacement struct {
	source, destination, backup string
	mode                        os.FileMode
	existed, installed          bool
}

// Backups stay on the install filesystem. Only the final rename replaces a
// live payload; a scheduling error can restore the previous files immediately.
func installUpdateFiles(stage string, files []*updateReplacement) (err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, restoreUpdateFiles(files))
		}
	}()
	for i, file := range files {
		file.backup = filepath.Join(stage, fmt.Sprintf("old-payload-%d", i))
		info, e := os.Stat(file.destination)
		if e == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("update target is not a regular file: %s", file.destination)
			}
			file.existed = true
			data, e := os.ReadFile(file.destination)
			if e != nil {
				return e
			}
			if e = os.WriteFile(file.backup, data, info.Mode().Perm()); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		if e = os.Chmod(file.source, file.mode); e != nil {
			return e
		}
		if e = os.Rename(file.source, file.destination); e != nil {
			return e
		}
		file.installed = true
	}
	return nil
}

func restoreUpdateFiles(files []*updateReplacement) error {
	var err error
	for i := len(files) - 1; i >= 0; i-- {
		file := files[i]
		if !file.installed {
			continue
		}
		var e error
		if file.existed {
			e = os.Rename(file.backup, file.destination)
		} else {
			e = os.Remove(file.destination)
		}
		if e != nil {
			err = errors.Join(err, fmt.Errorf("restore %s: %w", file.destination, e))
		} else {
			file.installed = false
		}
	}
	return err
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
