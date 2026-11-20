package service

import (
	"runtime/debug"
	"testing"
)

func TestLinkedSingboxVersion(t *testing.T) {
	for _, test := range []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{"missing", nil, ""},
		{"no dependency", &debug.BuildInfo{}, ""},
		{"module", &debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/sagernet/sing-box", Version: "v1.14.4"}}}, "1.14.4"},
		{"replacement", &debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/sagernet/sing-box", Version: "v1.14.4", Replace: &debug.Module{Version: "v1.14.5"}}}}, "1.14.5"},
		{"local replacement", &debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/sagernet/sing-box", Replace: &debug.Module{Path: "../sing-box"}}}}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := linkedSingboxVersion(test.info); got != test.want {
				t.Fatalf("version = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSystemInfoCoreVersion(t *testing.T) {
	if got := (&ServerService{}).GetSystemInfo()["coreVersion"]; got != singboxVersion {
		t.Fatalf("coreVersion = %v, want %q", got, singboxVersion)
	}
}
