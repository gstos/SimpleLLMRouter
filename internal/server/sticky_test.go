package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestStickyConversationGrowsWithoutChangingProvider(t *testing.T) {
	for _, instructions := range [][]map[string]string{
		nil,
		{{"role": "system", "content": "Be helpful"}},
		{{"role": "system", "content": "Be helpful"}, {"role": "developer", "content": "Be concise"}},
	} {
		h, ups := setup(t)
		messages := append([]map[string]string{}, instructions...)
		messages = append(messages, map[string]string{"role": "user", "content": "Hello"})
		body := map[string]any{"model": "gpt", "messages": messages}
		_, first := do(t, h, fullKey, "/v1/chat/completions", body)
		provider := first["from"]
		for i := 0; i < 3; i++ {
			messages = append(messages,
				map[string]string{"role": "assistant", "content": "Hi"},
				map[string]string{"role": "user", "content": "Continue"})
			body["messages"] = messages
			_, next := do(t, h, fullKey, "/v1/chat/completions", body)
			if next["from"] != provider {
				t.Fatalf("growing conversation moved from %v to %v", provider, next["from"])
			}
		}
		// The stable key must also preserve a failover pin as history grows.
		ups[provider.(string)].setFail(503)
		_, failedOver := do(t, h, fullKey, "/v1/chat/completions", body)
		if failedOver["from"] == provider {
			t.Fatal("request did not fail over")
		}
		ups[provider.(string)].setFail(0)
		messages = append(messages,
			map[string]string{"role": "assistant", "content": "More"},
			map[string]string{"role": "user", "content": "Again"})
		body["messages"] = messages
		_, next := do(t, h, fullKey, "/v1/chat/completions", body)
		if next["from"] != failedOver["from"] {
			t.Fatalf("lost failover pin: %v -> %v", failedOver["from"], next["from"])
		}
	}
}

func TestStickyPrefixIncludesFirstUserAfterInstructions(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	key := func(user string) string {
		messages, err := json.Marshal([]map[string]string{
			{"role": "system", "content": "shared system"},
			{"role": "developer", "content": "shared developer"},
			{"role": "user", "content": user},
		})
		if err != nil {
			t.Fatal(err)
		}
		return stickyKey("client", "gpt", req, map[string]json.RawMessage{"messages": messages})
	}
	if key("conversation one") == key("conversation two") {
		t.Fatal("different conversations with shared instructions got the same sticky key")
	}
}
