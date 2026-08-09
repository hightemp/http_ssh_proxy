package buildinfo

import (
	"runtime"
	"strings"
	"testing"
)

func TestCurrentAndString(t *testing.T) {
	originalVersion, originalCommit, originalBuildTime := Version, Commit, BuildTime
	t.Cleanup(func() {
		Version, Commit, BuildTime = originalVersion, originalCommit, originalBuildTime
	})

	Version = "v1.2.3"
	Commit = "abc123"
	BuildTime = "2026-08-09T12:00:00Z"

	info := Current()
	if info.Version != Version || info.Commit != Commit || info.BuildTime != BuildTime {
		t.Fatalf("Current() metadata = %+v", info)
	}
	if info.GoVersion != runtime.Version() || info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
		t.Fatalf("Current() runtime metadata = %+v", info)
	}

	for _, want := range []string{
		"version=v1.2.3",
		"commit=abc123",
		"built=2026-08-09T12:00:00Z",
		"go=" + runtime.Version(),
		"platform=" + runtime.GOOS + "/" + runtime.GOARCH,
	} {
		if !strings.Contains(String(), want) {
			t.Errorf("String() = %q, want substring %q", String(), want)
		}
	}
}
