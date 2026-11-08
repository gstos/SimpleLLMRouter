package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/configfile"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

// ---- client API keys ----

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage client API keys in the config file",
}

var (
	keyModels []string
	keyAdmin  bool
)

var keyAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Generate a client API key and add its hash to api_keys",
	Long: "Generate a client API key, store its SHA-256 hash in the config and print the key.\n" +
		"The key is shown only once; it cannot be recovered from the config.\n\n" +
		"  simple-router key add rag-service --models 'openai/text-embedding-*,cohere/*'\n" +
		"  simple-router key add ops --admin",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		models := keyModels
		if len(models) == 0 {
			models = []string{"*"}
		}
		key, err := auth.GenerateKey()
		if err != nil {
			return err
		}
		if err := f.AddAPIKey(configfile.APIKey{Name: args[0], Hash: auth.Hash(key), Models: models, Admin: keyAdmin}); err != nil {
			return err
		}
		if err := f.Save(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Added key %q (models: %s) to %s. Restart the server to apply.\n",
			args[0], strings.Join(models, ", "), v.GetString("config"))
		fmt.Fprintln(os.Stderr, "Save this key now, it will not be shown again:")
		fmt.Fprintln(cmd.OutOrStdout(), key)
		return nil
	},
}

var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List client API keys (names and access, never the keys)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		keys, err := f.List("api_keys")
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tADMIN\tMODELS")
		for _, k := range keys {
			models := fmt.Sprint(k["models"])
			if k["models"] == nil {
				models = "[*]"
			}
			fmt.Fprintf(tw, "%v\t%v\t%s\n", k["name"], k["admin"] == true, models)
		}
		return tw.Flush()
	},
}

var keyRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a client API key (revokes it after the server restarts)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return removeItem("api_keys", args[0])
	},
}

// ---- providers ----

var providerCmd = &cobra.Command{
	Use:   "provider",
	Short: "Manage upstream providers in the config file",
}

var (
	provBaseURL    string
	provAPIKey     string
	provNoAuth     bool
	provAuthHeader string
	provAuthScheme string
)

var providerAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a provider, encrypting its API key with the master key",
	Long: "Add a provider to the config. The provider API key is encrypted with the master key\n" +
		"before it is written. Pass it with --api-key, pipe it on stdin, or leave both out to be\n" +
		"prompted (input hidden). Use --no-auth for providers that need no key.\n\n" +
		"  simple-router provider add openai --base-url https://api.openai.com/v1\n" +
		"  printf %s \"$KEY\" | simple-router provider add openrouter --base-url https://openrouter.ai/api/v1\n" +
		"  simple-router provider add azure --base-url https://x.openai.azure.com/openai/v1 \\\n" +
		"      --auth-header api-key --auth-scheme none\n" +
		"  simple-router provider add vllm --base-url http://localhost:8000/v1 --no-auth\n\n" +
		"Other settings (headers, paths, health_method) can be edited in the YAML afterwards.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		u, err := url.Parse(provBaseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("--base-url %q is not an absolute URL", provBaseURL)
		}
		if provNoAuth && provAPIKey != "" {
			return errors.New("--no-auth and --api-key are mutually exclusive")
		}

		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		// Fail on a duplicate before asking for the secret.
		if existing, _ := f.List("providers"); hasName(existing, name) {
			return fmt.Errorf("provider %q already exists", name)
		}

		p := configfile.Provider{
			Name:       name,
			BaseURL:    strings.TrimRight(provBaseURL, "/"),
			AuthHeader: provAuthHeader,
			AuthScheme: provAuthScheme,
		}
		if !provNoAuth {
			// Verify the master key before asking for the provider key.
			ci, err := verifiedCipher(f)
			if err != nil {
				return err
			}
			if f.Scalar("master_key_check") == "" {
				f.SetScalar("master_key_check", ci.KeyCheck(), keyCheckComment)
			}
			secret := provAPIKey
			if secret == "" {
				if secret, err = readSecret(cmd.InOrStdin(), fmt.Sprintf("API key for %s: ", name)); err != nil {
					return err
				}
			}
			if secret == "" {
				return errors.New("empty API key (use --no-auth for providers without one)")
			}
			if p.APIKey, err = ci.Encrypt(secret); err != nil {
				return err
			}
		}

		if err := f.AddProvider(p); err != nil {
			return err
		}
		if err := f.Save(); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Added provider %q to %s.\n", name, v.GetString("config"))
		fmt.Fprintln(cmd.OutOrStdout(), "Reference it from models[].targets[].provider, then restart the server.")
		return nil
	},
}

var providerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List providers",
	RunE: func(cmd *cobra.Command, _ []string) error {
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		provs, err := f.List("providers")
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tBASE URL\tAUTH")
		for _, p := range provs {
			authDesc := "none"
			if k, _ := p["api_key"].(string); k != "" {
				authDesc = "encrypted"
				if !strings.HasPrefix(k, "enc:v1:") {
					authDesc = "PLAINTEXT (re-add with `provider add`)"
				}
			}
			fmt.Fprintf(tw, "%v\t%v\t%s\n", p["name"], p["base_url"], authDesc)
		}
		return tw.Flush()
	},
}

var providerRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a provider (refused while models still use it)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		models, err := f.List("models")
		if err != nil {
			return err
		}
		var users []string
		for _, m := range models {
			targets, _ := m["targets"].([]any)
			for _, t := range targets {
				if tm, ok := t.(map[string]any); ok && tm["provider"] == args[0] {
					users = append(users, fmt.Sprint(m["name"]))
					break
				}
			}
		}
		if len(users) > 0 {
			return fmt.Errorf("provider %q is used by models: %s; remove those targets first", args[0], strings.Join(users, ", "))
		}
		return removeItem("providers", args[0])
	},
}

func removeItem(section, name string) error {
	f, err := configfile.Load(v.GetString("config"))
	if err != nil {
		return err
	}
	if !f.Remove(section, name) {
		return fmt.Errorf("%s: %q not found", section, name)
	}
	if err := f.Save(); err != nil {
		return err
	}
	fmt.Printf("Removed %q from %s. Restart the server to apply.\n", name, section)
	return nil
}

func hasName(entries []configfile.Entry, name string) bool {
	for _, e := range entries {
		if e["name"] == name {
			return true
		}
	}
	return false
}

// verifiedCipher returns the master key cipher after checking it against the
// config: master_key_check if present, and every existing encrypted value.
func verifiedCipher(f *configfile.File) (*secrets.Cipher, error) {
	ci, err := interactiveCipher()
	if err != nil {
		return nil, err
	}
	if check := f.Scalar("master_key_check"); check != "" && !ci.VerifyKeyCheck(check) {
		return nil, config.ErrWrongMasterKey
	}
	provs, err := f.List("providers")
	if err != nil {
		return nil, err
	}
	for _, p := range provs {
		if v, _ := p["api_key"].(string); secrets.IsEncrypted(v) {
			// Only authentication failures prove a wrong key; malformed placeholders are skipped.
			if _, err := ci.Decrypt(v); errors.Is(err, secrets.ErrDecrypt) {
				return nil, fmt.Errorf("wrong master key: it cannot decrypt the api_key of provider %q", p["name"])
			}
		}
	}
	return ci, nil
}

// interactiveCipher is masterCipher, but prompts for the master key (hidden)
// when none is configured and stdin is a terminal.
func interactiveCipher() (*secrets.Cipher, error) {
	ci, err := masterCipher()
	if !errors.Is(err, errNoMasterKey) || !stdinIsTerminal() {
		return ci, err
	}
	key, err := readSecret(os.Stdin, "Master key: ")
	if err != nil {
		return nil, err
	}
	return secrets.New(key)
}

func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// readSecret prompts with hidden input on a terminal, or reads one line from piped stdin.
func readSecret(in io.Reader, prompt string) (string, error) {
	if fd := int(os.Stdin.Fd()); in == os.Stdin && stdinIsTerminal() {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	sc.Scan()
	return strings.TrimSpace(sc.Text()), sc.Err()
}

func init() {
	keyAddCmd.Flags().StringSliceVar(&keyModels, "models", nil, "models the key may use, comma separated; globs allowed (default: all)")
	keyAddCmd.Flags().BoolVar(&keyAdmin, "admin", false, "allow the key to call /admin endpoints")
	keyCmd.AddCommand(keyAddCmd, keyListCmd, keyRemoveCmd)

	f := providerAddCmd.Flags()
	f.StringVar(&provBaseURL, "base-url", "", "OpenAI-compatible API base URL, e.g. https://api.openai.com/v1 (required)")
	f.StringVar(&provAPIKey, "api-key", "", "provider API key (prompted or read from stdin if omitted; note: flags end up in shell history)")
	f.BoolVar(&provNoAuth, "no-auth", false, "provider needs no API key")
	f.StringVar(&provAuthHeader, "auth-header", "", "header carrying the key (default Authorization)")
	f.StringVar(&provAuthScheme, "auth-scheme", "", "prefix before the key (default Bearer; \"none\" sends the raw key)")
	_ = providerAddCmd.MarkFlagRequired("base-url")
	providerCmd.AddCommand(providerAddCmd, providerListCmd, providerRemoveCmd)
}
