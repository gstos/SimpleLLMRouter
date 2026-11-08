package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/configfile"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

const keyCheckComment = "Identifies the master key (not secret). Commands refuse a different key."

// ---- init ----

var initListen string

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "First-time setup: master key file, starter config and an admin client key",
	Long: "Create a master key file (0600), a starter config containing master_key_check and an\n" +
		"'admin' client key with access to all models. The admin key is printed once.\n" +
		"Refuses to overwrite an existing key file or config.\n\n" +
		"  simple-router init                       # ./master.key and ./config.yaml\n" +
		"  simple-router init -c /etc/simple-router/config.yaml --master-key-file /etc/simple-router/master.key",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfgPath := v.GetString("config")
		keyPath := v.GetString("master_key_file")
		if keyPath == "" {
			keyPath = filepath.Join(filepath.Dir(cfgPath), "master.key")
		}

		f, err := configfile.Load(cfgPath)
		if err != nil {
			return err
		}
		if f.Exists() {
			return fmt.Errorf("%s already exists; init only creates new configs (use `provider add` / `key add` to extend it)", cfgPath)
		}

		mk, err := secrets.GenerateKey()
		if err != nil {
			return err
		}
		ci, err := secrets.New(mk)
		if err != nil {
			return err
		}
		adminKey, err := auth.GenerateKey()
		if err != nil {
			return err
		}

		// Key file first: a config whose master_key_check points to a lost key is useless.
		if err := writeNewSecretFile(keyPath, mk+"\n"); err != nil {
			return err
		}
		f.SetScalar("master_key_check", ci.KeyCheck(), keyCheckComment)
		if err := f.SetMapping("server", map[string]string{"listen": initListen}); err != nil {
			return err
		}
		if err := f.AddAPIKey(configfile.APIKey{Name: "admin", Hash: auth.Hash(adminKey), Models: []string{"*"}, Admin: true}); err != nil {
			return err
		}
		if err := f.Save(); err != nil {
			os.Remove(keyPath)
			return err
		}

		e := os.Stderr
		fmt.Fprintf(e, "Created %s (master key, keep it secret and backed up)\n", keyPath)
		fmt.Fprintf(e, "Created %s with an 'admin' client key\n\n", cfgPath)
		fmt.Fprintln(e, "Admin API key (shown once, save it now):")
		fmt.Fprintln(cmd.OutOrStdout(), adminKey)
		absKey, _ := filepath.Abs(keyPath)
		fmt.Fprintf(e, "\nNext:\n  export SIMPLE_ROUTER_MASTER_KEY_FILE=%s\n", absKey)
		fmt.Fprintf(e, "  simple-router -c %s provider add <name> --base-url <url>\n", cfgPath)
		fmt.Fprintf(e, "  # add models[] to %s, then: simple-router -c %s serve\n", cfgPath, cfgPath)
		return nil
	},
}

// ---- rotate ----

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the master key, a client key or a provider credential",
}

var rotateOut string

var rotateMasterCmd = &cobra.Command{
	Use:   "master-key",
	Short: "Re-encrypt all provider credentials under a new master key",
	Long: "Generate a new master key, re-encrypt every provider api_key with it and update\n" +
		"master_key_check. The current key is verified first.\n\n" +
		"If the current key came from a file, that file is replaced (the new key is written to\n" +
		"<file>.new first, then the config, then the rename, so an interruption never loses a key).\n" +
		"Otherwise pass --out for the new key file. Restart the server with the new key afterwards.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfgPath := v.GetString("config")
		f, err := configfile.Load(cfgPath)
		if err != nil {
			return err
		}
		if !f.Exists() {
			return fmt.Errorf("%s not found", cfgPath)
		}
		oldCi, err := verifiedCipher(f)
		if err != nil {
			return err
		}

		out := rotateOut
		inPlace := false
		if out == "" {
			if v.GetString("master_key") != "" || v.GetString("master_key_file") == "" {
				return errors.New("the current key did not come from a file; pass --out for the new key file")
			}
			out, inPlace = v.GetString("master_key_file"), true
		}

		mk, err := secrets.GenerateKey()
		if err != nil {
			return err
		}
		newCi, err := secrets.New(mk)
		if err != nil {
			return err
		}

		provs, err := f.List("providers")
		if err != nil {
			return err
		}
		n := 0
		for _, p := range provs {
			name, _ := p["name"].(string)
			val := f.Field("providers", name, "api_key")
			if !secrets.IsEncrypted(val) {
				continue
			}
			pt, err := oldCi.Decrypt(val)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: provider %q: %v; left unchanged\n", name, err)
				continue
			}
			enc, err := newCi.Encrypt(pt)
			if err != nil {
				return err
			}
			f.SetField("providers", name, "api_key", enc)
			n++
		}
		f.SetScalar("master_key_check", newCi.KeyCheck(), keyCheckComment)

		writePath := out
		if inPlace {
			writePath = out + ".new"
		}
		if err := writeNewSecretFile(writePath, mk+"\n"); err != nil {
			return err
		}
		if err := f.Save(); err != nil {
			os.Remove(writePath)
			return fmt.Errorf("saving config (nothing changed): %w", err)
		}
		if inPlace {
			if err := os.Rename(writePath, out); err != nil {
				return fmt.Errorf("config now uses the key in %s, but replacing %s failed: %w", writePath, out, err)
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Re-encrypted %d provider credential(s); new master key in %s.\n", n, out)
		fmt.Fprintln(cmd.OutOrStdout(), "Restart the server with the new key. The old key no longer decrypts this config.")
		return nil
	},
}

var rotateKeyCmd = &cobra.Command{
	Use:   "key <name>",
	Short: "Issue a new client API key for <name>, keeping its access; the old key stops working",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		key, err := auth.GenerateKey()
		if err != nil {
			return err
		}
		if !f.SetField("api_keys", args[0], "hash", auth.Hash(key)) {
			return fmt.Errorf("api_keys: %q not found", args[0])
		}
		if err := f.Save(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Rotated key %q. The old key stops working when the server restarts.\n", args[0])
		fmt.Fprintln(os.Stderr, "New key (shown once, save it now):")
		fmt.Fprintln(cmd.OutOrStdout(), key)
		return nil
	},
}

var rotateProviderKey string

var rotateProviderCmd = &cobra.Command{
	Use:   "provider <name>",
	Short: "Replace a provider's upstream API key (prompted, piped, or --api-key)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		if provs, _ := f.List("providers"); !hasName(provs, name) {
			return fmt.Errorf("provider %q not found", name)
		}
		ci, err := verifiedCipher(f)
		if err != nil {
			return err
		}
		if f.Scalar("master_key_check") == "" {
			f.SetScalar("master_key_check", ci.KeyCheck(), keyCheckComment)
		}
		secret := rotateProviderKey
		if secret == "" {
			if secret, err = readSecret(cmd.InOrStdin(), fmt.Sprintf("New API key for %s: ", name)); err != nil {
				return err
			}
		}
		if secret == "" {
			return errors.New("empty API key")
		}
		enc, err := ci.Encrypt(secret)
		if err != nil {
			return err
		}
		f.SetField("providers", name, "api_key", enc)
		if err := f.Save(); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Updated the API key of provider %q. Restart the server to apply.\n", name)
		return nil
	},
}

// writeNewSecretFile creates path with mode 0600, refusing to overwrite.
func writeNewSecretFile(path, content string) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; refusing to overwrite a key file", path)
	}
	if err != nil {
		return err
	}
	if _, err := fh.WriteString(content); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

func init() {
	initCmd.Flags().StringVar(&initListen, "listen", ":8080", "server.listen for the starter config")
	rotateMasterCmd.Flags().StringVar(&rotateOut, "out", "", "file for the new master key (default: replace the current --master-key-file)")
	rotateProviderCmd.Flags().StringVar(&rotateProviderKey, "api-key", "", "new provider API key (prompted or read from stdin if omitted)")
	rotateCmd.AddCommand(rotateMasterCmd, rotateKeyCmd, rotateProviderCmd)
}
