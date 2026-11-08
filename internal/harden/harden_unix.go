//go:build unix && !linux

package harden

import "golang.org/x/sys/unix"

func apply(r *Result) {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		r.Failed["no-core-dumps"] = err
	} else {
		r.Applied = append(r.Applied, "no-core-dumps")
	}
}
