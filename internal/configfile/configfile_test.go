package configfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `# top comment
server:
  listen: ":8080" # inline
providers:
  - name: a
    base_url: http://a
models:
  - name: m
    targets:
      - { provider: a }
`

func TestAddListRemovePreservesComments(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(sample), 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AddProvider(Provider{Name: "b", BaseURL: "http://b", APIKey: "enc:v1:x"}); err != nil {
		t.Fatal(err)
	}
	if err := f.AddProvider(Provider{Name: "a", BaseURL: "http://dup"}); err == nil {
		t.Fatal("duplicate provider accepted")
	}
	if err := f.AddAPIKey(APIKey{Name: "k", Hash: "sha256:00", Models: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(p)
	out := string(b)
	for _, want := range []string{"# top comment", "# inline", "name: b", "api_keys:", "models: ['*']", "{provider: a}"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %v", st.Mode().Perm())
	}

	f, _ = Load(p)
	provs, _ := f.List("providers")
	if len(provs) != 2 || provs[1]["name"] != "b" {
		t.Fatalf("providers: %v", provs)
	}
	models, _ := f.List("models")
	targets := models[0]["targets"].([]any)
	if targets[0].(map[string]any)["provider"] != "a" {
		t.Fatalf("nested decode: %#v", targets)
	}
	if !f.Remove("providers", "b") || f.Remove("providers", "zzz") {
		t.Fatal("remove")
	}
}

func TestNewFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "new.yaml")
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.AddAPIKey(APIKey{Name: "k", Hash: "sha256:00", Models: []string{"*"}})
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("new file mode %v, want 0600", st.Mode().Perm())
	}
}
