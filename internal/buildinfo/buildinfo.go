// Package buildinfo exposes metadata embedded in release binaries.
package buildinfo

import (
	"fmt"
	"runtime"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Info describes the source and toolchain used to build the executable.
type Info struct {
	Version   string
	Commit    string
	BuildTime string
	GoVersion string
	OS        string
	Arch      string
}

// Current returns the metadata for the running executable.
func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns a stable, human-readable metadata line.
func String() string {
	info := Current()
	return fmt.Sprintf(
		"http_ssh_proxy version=%s commit=%s built=%s go=%s platform=%s/%s",
		info.Version,
		info.Commit,
		info.BuildTime,
		info.GoVersion,
		info.OS,
		info.Arch,
	)
}
