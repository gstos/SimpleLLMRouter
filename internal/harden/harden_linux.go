package harden

import "golang.org/x/sys/unix"

func apply(r *Result) {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		r.Failed["no-core-dumps"] = err
	} else {
		r.Applied = append(r.Applied, "no-core-dumps")
	}
	// Non-dumpable: no core dumps even if the limit is raised, and processes of
	// the same uid can no longer ptrace us or read /proc/<pid>/mem.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		r.Failed["non-dumpable"] = err
	} else {
		r.Applied = append(r.Applied, "non-dumpable")
	}
}
