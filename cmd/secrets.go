package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new master key",
	RunE: func(cmd *cobra.Command, _ []string) error {
		k, err := secrets.GenerateKey()
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), k)
		return nil
	},
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt [secret]",
	Short: "Encrypt a provider API key for the config (reads stdin if no argument)",
	Long: "Encrypt a provider API key with the master key. Prefer piping the secret via stdin\n" +
		"so it doesn't end up in your shell history:\n\n  printf %s \"$OPENAI_API_KEY\" | simple-router encrypt",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ci, err := masterCipher()
		if err != nil {
			return err
		}
		var secret string
		if len(args) == 1 {
			secret = args[0]
		} else {
			sc := bufio.NewScanner(cmd.InOrStdin())
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			if sc.Scan() {
				secret = sc.Text()
			}
			if err := sc.Err(); err != nil {
				return err
			}
		}
		secret = strings.TrimSpace(secret)
		if secret == "" {
			return errors.New("empty secret")
		}
		out, err := ci.Encrypt(secret)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), out)
		return nil
	},
}

var apikeyCmd = &cobra.Command{
	Use:   "apikey [existing-key]",
	Short: "Generate a client API key and the hash to put in api_keys[].hash",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var key string
		if len(args) == 1 {
			key = args[0]
		} else {
			var err error
			if key, err = auth.GenerateKey(); err != nil {
				return err
			}
		}
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "key:  %s\nhash: %s\n", key, auth.Hash(key))
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Give the key to the client; only the hash goes in the config.")
		}
		return nil
	},
}
