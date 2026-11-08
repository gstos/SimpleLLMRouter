package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
		"Otherwise pass --out for the new key file. Restart the server with the new key afterwards.\n\n" +
		"With --api, a running router does the rotation itself (POST /admin/rotate-master-key):\n" +
		"no restart; it replaces its key file if it uses one. The new key is written to --out,\n" +
		"or printed if --out is not given.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if rotateViaAPI {
			return rotateMasterViaAPI(cmd)
		}
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
		n, _, err := rotateMaster(f, oldCi, mk, out, inPlace, func(msg string) { fmt.Fprintln(os.Stderr, "warning:", msg) })
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Re-encrypted %d provider credential(s); new master key in %s.\n", n, out)
		fmt.Fprintln(cmd.OutOrStdout(), "Restart the server with the new key. The old key no longer decrypts this config.")
		return nil
	},
}

var (
	rotateViaAPI bool
	rotateAPIURL string
	rotateAPIKey string
)

func rotateMasterViaAPI(cmd *cobra.Command) error {
	current, err := interactiveMasterKey()
	if err != nil {
		return err
	}
	// Fail on an existing --out before the router rotates anything.
	if rotateOut != "" {
		if _, err := os.Stat(rotateOut); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite a key file", rotateOut)
		}
	}
	out, err := keyAdminCall(cmd, "/admin/rotate-master-key", rotateAPIURL, rotateAPIKey, map[string]string{"master_key": current})
	if err != nil {
		return err
	}
	newKey, _ := out["master_key"].(string)
	if newKey == "" {
		return errors.New("router did not return the new master key")
	}
	if rotateOut == "" {
		fmt.Fprintln(os.Stderr, "Rotated. New master key (shown once, store it now):")
		fmt.Fprintln(cmd.OutOrStdout(), newKey)
		return nil
	}
	if err := writeNewSecretFile(rotateOut, newKey+"\n"); err != nil {
		fmt.Fprintln(os.Stderr, "Rotated, but writing the key file failed. New master key (store it now):")
		fmt.Fprintln(cmd.OutOrStdout(), newKey)
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Rotated; new master key in %s. The router is already using it.\n", rotateOut)
	return nil
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

// rotateMaster re-encrypts every provider credential in f from oldCi to newKey,
// updates master_key_check and saves f. When keyOut is set the new key is
// written there first; with inPlace it goes to keyOut+".new" and is renamed over
// keyOut after the config is saved, so an interruption never loses the key that
// matches the config. Values that can't be decrypted are left as is (warn).
func rotateMaster(f *configfile.File, oldCi *secrets.Cipher, newKey, keyOut string, inPlace bool, warn func(string)) (int, *secrets.Cipher, error) {
	newCi, err := secrets.New(newKey)
	if err != nil {
		return 0, nil, err
	}
	provs, err := f.List("providers")
	if err != nil {
		return 0, nil, err
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
			warn(fmt.Sprintf("provider %q: %v; left unchanged", name, err))
			continue
		}
		enc, err := newCi.Encrypt(pt)
		if err != nil {
			return 0, nil, err
		}
		f.SetField("providers", name, "api_key", enc)
		n++
	}
	f.SetScalar("master_key_check", newCi.KeyCheck(), keyCheckComment)

	writePath := keyOut
	if inPlace {
		writePath = keyOut + ".new"
	}
	if keyOut != "" {
		if err := writeNewSecretFile(writePath, strings.TrimSpace(newKey)+"\n"); err != nil {
			return 0, nil, err
		}
	}
	if err := f.Save(); err != nil {
		if keyOut != "" {
			os.Remove(writePath)
		}
		return 0, nil, fmt.Errorf("saving config (nothing changed): %w", err)
	}
	if inPlace {
		if err := os.Rename(writePath, keyOut); err != nil {
			return n, newCi, fmt.Errorf("config now uses the key in %s, but replacing %s failed: %w", writePath, keyOut, err)
		}
	}
	return n, newCi, nil
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
	rotateMasterCmd.Flags().StringVar(&rotateOut, "out", "", "file for the new master key (default: replace the current --master-key-file; with --api: print it)")
	rotateMasterCmd.Flags().BoolVar(&rotateViaAPI, "api", false, "ask a running router to rotate (POST /admin/rotate-master-key)")
	rotateMasterCmd.Flags().StringVar(&rotateAPIURL, "url", "", "with --api: router base URL (default: from server.listen)")
	rotateMasterCmd.Flags().StringVar(&rotateAPIKey, "api-key", "", "with --api: admin client API key (prefer SIMPLE_ROUTER_API_KEY or the prompt)")
	rotateProviderCmd.Flags().StringVar(&rotateProviderKey, "api-key", "", "new provider API key (prompted or read from stdin if omitted)")
	rotateCmd.AddCommand(rotateMasterCmd, rotateKeyCmd, rotateProviderCmd)
}
