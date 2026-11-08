package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

func TestMasterKeyCallDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var hits atomic.Int32
			dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			defer dest.Close()
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, dest.URL, status)
			}))
			defer source.Close()
			mk, err := secrets.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			_, err = keyAdminCall(cmd, "/admin/unseal", source.URL, "admin-secret", map[string]string{"master_key": mk})
			if err == nil {
				t.Fatal("redirect was not rejected")
			}
			if hits.Load() != 0 {
				t.Fatal("redirect destination received the master key request")
			}
		})
	}
}
