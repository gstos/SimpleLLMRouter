package cmd

import "testing"

func TestIsLocalURL(t *testing.T) {
	for _, raw := range []string{
		"http://localhost:8080", "https://LOCALHOST", "https://127.0.0.1",
		"http://127.1.2.3:9000", "https://[::1]:8443", "https://[::ffff:127.0.0.1]",
	} {
		if !isLocalURL(raw) {
			t.Errorf("loopback URL rejected: %s", raw)
		}
	}
	for _, raw := range []string{
		"https://localhost.attacker.example", "https://127.attacker.example",
		"https://attacker.example/path/://localhost", "https://localhost@attacker.example",
		"https://192.168.1.1", "https://[::2]", "https://127.0.0.1.attacker.example",
		"https://%zz", "file://localhost/secret", "/://localhost",
	} {
		if isLocalURL(raw) {
			t.Errorf("non-loopback URL accepted: %s", raw)
		}
	}
}

func TestClientTLSRejectsRemoteInsecure(t *testing.T) {
	previous := clientInsecure
	clientInsecure = true
	t.Cleanup(func() { clientInsecure = previous })
	for _, raw := range []string{"https://localhost.attacker.example", "https://127.attacker.example"} {
		if _, err := clientTLS(raw, nil); err == nil {
			t.Errorf("--insecure accepted for remote URL %s", raw)
		}
	}
}
