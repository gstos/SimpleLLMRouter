package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

var (
	unsealURL    string
	unsealAPIKey string
)

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Send the master key to a running (sealed) router",
	Long: "Post the master key to the router's /admin/unseal endpoint. Works on a sealed router\n" +
		"and on a running one (applies a rotated master key live).\n\n" +
		"Master key: --master-key-file / env, else prompted (hidden), else one line from stdin.\n" +
		"Admin client key: --api-key or SIMPLE_ROUTER_API_KEY, else prompted (hidden).\n" +
		"URL: --url, else derived from server.listen in the config (localhost).\n\n" +
		"  simple-router unseal\n" +
		"  docker exec -it <container> simple-router unseal\n" +
		"  simple-router unseal --url https://router.example.com   # server needs --allow-remote-key-admin",
	RunE: func(cmd *cobra.Command, _ []string) error {
		mk, err := interactiveMasterKey()
		if noKeyConfigured(err) {
			mk, err = readSecret(cmd.InOrStdin(), "") // piped stdin
		}
		if err != nil {
			return err
		}
		if _, err := keyAdminCall(cmd, "/admin/unseal", unsealURL, unsealAPIKey, map[string]string{"master_key": mk}); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "unsealed")
		return nil
	},
}

// keyAdminCall posts payload to a master key endpoint of a running router and
// returns the decoded JSON response. The admin client key comes from apiKey,
// SIMPLE_ROUTER_API_KEY or a prompt; the URL from baseURL or server.listen.
func keyAdminCall(cmd *cobra.Command, path, baseURL, apiKey string, payload map[string]string) (map[string]any, error) {
	for k, val := range payload {
		val = strings.TrimSpace(val)
		payload[k] = val
		if strings.HasSuffix(k, "master_key") && val != "" {
			if _, err := secrets.New(val); err != nil { // catch typos before sending
				return nil, fmt.Errorf("%s: %w", k, err)
			}
		}
	}

	url := strings.TrimRight(baseURL, "/")
	var cfg *config.Config
	if url == "" {
		base, c, err := localEndpoint()
		if err != nil {
			return nil, fmt.Errorf("%w (or pass --url)", err)
		}
		url, cfg = base, c
	} else if c, err := loadConfig(); err == nil {
		cfg = c // used to trust the router's self-signed certificate, if any
	}
	url = strings.TrimSuffix(url, path) + path
	tlsConf, err := clientTLS(url, cfg)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(url, "http://") && !isLocalURL(url) {
		fmt.Fprintln(os.Stderr, "warning: sending the master key over plain HTTP to a non-local address")
	}

	if apiKey == "" {
		apiKey = os.Getenv("SIMPLE_ROUTER_API_KEY")
	}
	if apiKey == "" {
		if !stdinIsTerminal() {
			return nil, errors.New("admin API key required: --api-key or SIMPLE_ROUTER_API_KEY")
		}
		var err error
		if apiKey, err = readSecret(os.Stdin, "Admin API key: "); err != nil {
			return nil, err
		}
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConf
	resp, err := (&http.Client{Timeout: 60 * time.Second, Transport: tr}).Do(req)
	if err != nil && strings.Contains(err.Error(), "certificate") {
		return nil, fmt.Errorf("%w\n(trust the router's CA with --ca-file; for a local router, --insecure skips verification)", err)
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		if e, ok := out["error"].(map[string]any); ok {
			return nil, fmt.Errorf("%s failed (%d): %v", path, resp.StatusCode, e["message"])
		}
		return nil, fmt.Errorf("%s failed (%d): %s", path, resp.StatusCode, bytes.TrimSpace(raw))
	}
	return out, nil
}

func isLocalURL(u string) bool {
	for _, h := range []string{"://127.", "://localhost", "://[::1]"} {
		if strings.Contains(u, h) {
			return true
		}
	}
	return false
}

func init() {
	unsealCmd.Flags().StringVar(&unsealURL, "url", "", "router base URL (default: from server.listen in the config)")
	unsealCmd.Flags().StringVar(&unsealAPIKey, "api-key", "", "admin client API key (prefer SIMPLE_ROUTER_API_KEY or the prompt)")
	addClientTLSFlags(unsealCmd)
}
