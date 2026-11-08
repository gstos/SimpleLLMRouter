package harden

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyLinux(t *testing.T) {
	r := Apply()
	if len(r.Failed) > 0 {
		t.Fatalf("failed: %v", r.Failed)
	}
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || d != 0 {
		t.Fatalf("dumpable = %d, %v; want 0", d, err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil || lim.Cur != 0 {
		t.Fatalf("core limit = %d, %v; want 0", lim.Cur, err)
	}
}
