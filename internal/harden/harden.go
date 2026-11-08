// Package harden reduces how easily the router's memory (master key, decrypted
// provider credentials) can be read by other processes or end up on disk.
//
// It cannot protect against root on the host; it closes the cheap paths:
// core dumps, and ptrace / /proc/<pid>/mem access by processes of the same user.
package harden

// Result lists what was applied and what failed (failures are not fatal).
type Result struct {
	Applied []string
	Failed  map[string]error
}

// Apply hardens the current process. Call it before any secret is loaded.
func Apply() Result {
	r := Result{Failed: map[string]error{}}
	apply(&r)
	return r
}
