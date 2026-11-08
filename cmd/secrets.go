package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/configfile"
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
		// Check the key against the config when there is one; plain encryption otherwise.
		var ci *secrets.Cipher
		var err error
		if f, lerr := configfile.Load(v.GetString("config")); lerr == nil {
			ci, err = verifiedCipher(f)
		} else {
			ci, err = interactiveCipher()
		}
		if err != nil {
			return err
		}
		var secret string
		if len(args) == 1 {
			secret = args[0]
		} else if secret, err = readSecret(cmd.InOrStdin(), "Secret: "); err != nil {
			return err
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
	Short: "Print a client API key and its hash without editing the config (see `key add`)",
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
