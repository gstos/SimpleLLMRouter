package cmd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

var (
	pingURL     string
	pingTimeout time.Duration
)

// pingCmd checks the local server's /healthz. It needs no master key and no
// external tools, so it works as a container HEALTHCHECK in a distroless image.
var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Check that a running router answers on /healthz (for container health checks)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		url := pingURL
		if url == "" {
			base, err := localBaseURL()
			if err != nil {
				return err
			}
			url = base + "/healthz"
		}
		client := &http.Client{Timeout: pingTimeout}
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned %d", url, resp.StatusCode)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "ok")
		return nil
	},
}

// localBaseURL is the router's own address from server.listen, via loopback.
// It reads only the YAML (no master key needed).
func localBaseURL() (string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return "", err
	}
	return "http://" + loopback(cfg.Server.Listen), nil
}

// loopback turns a listen address like ":8080" or "0.0.0.0:8080" into a dialable local one.
func loopback(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func init() {
	pingCmd.Flags().StringVar(&pingURL, "url", "", "health URL (default: derived from server.listen in the config)")
	pingCmd.Flags().DurationVar(&pingTimeout, "timeout", 3*time.Second, "request timeout")
}
