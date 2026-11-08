package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/health"
)

var healthJSON bool

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Probe every configured provider and report its health (requires the master key)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadDecryptedConfig()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Server.HealthTimeout+5*time.Second)
		defer cancel()
		results := health.New(cfg.Providers, cfg.Server.HealthTimeout, nil).CheckAll(ctx)

		out := cmd.OutOrStdout()
		if healthJSON {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			if err := enc.Encode(results); err != nil {
				return err
			}
		} else {
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "PROVIDER\tSTATUS\tHTTP\tLATENCY\tERROR")
			for _, r := range results {
				st := "ok"
				if !r.Healthy {
					st = "DOWN"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%dms\t%s\n", r.Provider, st, r.Status, r.LatencyMS, r.Error)
			}
			tw.Flush()
		}
		for _, r := range results {
			if !r.Healthy {
				return fmt.Errorf("one or more providers are unhealthy")
			}
		}
		return nil
	},
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the config; with a master key, also check that all secrets decrypt",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if _, err := masterCipher(); !errors.Is(err, errNoMasterKey) {
			if _, err := loadDecryptedConfig(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "config OK, all secrets decrypt")
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "config OK (%d providers, %d models, %d keys); no master key given, secrets not checked\n",
			len(cfg.Providers), len(cfg.Models), len(cfg.APIKeys))
		return nil
	},
}

func init() {
	healthCmd.Flags().BoolVar(&healthJSON, "json", false, "output JSON")
}
