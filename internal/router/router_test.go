package router

import (
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

func testConfig(models ...config.Model) *config.Config {
	cfg := &config.Config{
		Providers: []config.Provider{{Name: "a", BaseURL: "http://a"}, {Name: "b", BaseURL: "http://b"}},
		Models:    models,
	}
	cfg.ApplyDefaults()
	return cfg
}

var model = config.Model{Name: "m", Targets: []config.Target{
	{Provider: "a", Priority: 1},
	{Provider: "b", Priority: 1},
}}

func TestReloadKeepsStickyAndCooldown(t *testing.T) {
	r1 := New(testConfig(model), nil)
	rt, _ := r1.Route("m")

	pinned := r1.Plan(rt, "sess")[1] // pin the session to the second target in order
	r1.Success("sess", pinned)
	other := r1.Plan(rt, "x")[0]
	if other == pinned {
		other = r1.Plan(rt, "x")[0]
	}
	r1.Failure(other)

	// Reload: same model plus a new one.
	r2 := New(testConfig(model, config.Model{Name: "n", Targets: []config.Target{{Provider: "a"}}}), r1)
	rt2, _ := r2.Route("m")
	for i := 0; i < 4; i++ {
		if got := r2.Plan(rt2, "sess")[0]; got.ID != pinned.ID {
			t.Fatalf("sticky lost across reload: got %s want %s", got.ID, pinned.ID)
		}
	}
	for i := 0; i < 4; i++ {
		if p := r2.Plan(rt2, "y"); p[len(p)-1].ID != other.ID {
			t.Fatalf("cooldown lost across reload: plan %s,%s", p[0].ID, p[1].ID)
		}
	}
}

func TestStickyExpires(t *testing.T) {
	cfg := testConfig(model)
	cfg.Server.StickyTTL = time.Minute
	r := New(cfg, nil)
	now := time.Now()
	r.sticky.now = func() time.Time { return now }
	rt, _ := r.Route("m")
	t0 := r.Plan(rt, "s")[1]
	r.Success("s", t0)
	if r.Plan(rt, "s")[0] != t0 {
		t.Fatal("not sticky")
	}
	now = now.Add(2 * time.Minute)
	firsts := map[string]bool{}
	for i := 0; i < 4; i++ {
		firsts[r.Plan(rt, "s")[0].ID] = true
	}
	if len(firsts) != 2 {
		t.Fatalf("expired pin still applied: %v", firsts)
	}
}
