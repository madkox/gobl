package main

import "runtime/debug"

// version can be set at build time with -ldflags "-X main.version=...".
// If it is not set, it comes from Go's build info.
var version string

// getVersion returns, in order of preference:
//   - the version set with -ldflags (make build);
//   - the module version, e.g. v0.1.0 (go install ...@v0.1.0 or @latest);
//   - the VCS revision for builds from a checkout, e.g. 1a2b3c4d5e6f-dirty;
//   - "dev".
func getVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}
