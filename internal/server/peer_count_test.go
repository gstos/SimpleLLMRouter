package server

// n returns how many requests the upstream has seen.
func (u *anthUpstream) n() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}
