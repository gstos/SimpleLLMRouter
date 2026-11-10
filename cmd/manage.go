package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
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
	keyProvs  []string
	keyNoExt  bool
)

var keyAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Generate a client API key and add its hash to api_keys",
	Long: "Generate a client API key, store its SHA-256 hash in the config and print the key.\n" +
		"The key is shown only once; it cannot be recovered from the config.\n\n" +
		"  simple-router key add rag-service --models 'openai/text-embedding-*,cohere/*'\n" +
		"  simple-router key add ops --admin\n" +
		"  simple-router key add notes --models bge-m3 --providers laya   # also /provider/laya/...",
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
		if err := f.AddAPIKey(configfile.APIKey{Name: args[0], Hash: auth.Hash(key), Models: models, Admin: keyAdmin, Providers: keyProvs, DisableExternal: keyNoExt}); err != nil {
			return err
		}
		if err := f.Save(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Added key %q (models: %s) to %s. A running router applies it automatically.\n",
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
		fmt.Fprintln(tw, "NAME\tADMIN\tNO EXTERNAL\tMODELS\tPROVIDERS")
		for _, k := range keys {
			models := fmt.Sprint(k["models"])
			if k["models"] == nil {
				models = "[*]"
			}
			provs := "-"
			if k["providers"] != nil {
				provs = fmt.Sprint(k["providers"])
			}
			fmt.Fprintf(tw, "%v\t%v\t%v\t%s\t%s\n", k["name"], k["admin"] == true, k["disable_external"] == true, models, provs)
		}
		return tw.Flush()
	},
}

var keyRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a client API key (a running router revokes it on reload)",
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
	provSessionHdr string
	provAuth       string
	provExternal   bool
	provPeer       bool
	provCAFile     string
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
		"  simple-router provider add vllm --base-url http://localhost:8000/v1 --no-auth\n" +
		"  simple-router provider add opencode-go --base-url https://opencode.ai/zen/go/v1 \\\n" +
		"      --auth passthrough --session-header X-Opencode-Session\n\n" +
		"  simple-router provider add router-b --base-url https://router-b.lan:8443/v1 --peer \\\n" +
		"      --ca-file /etc/sr/router-b.pem\n" +
		"  simple-router provider add openrouter --base-url https://openrouter.ai/api/v1 --external\n\n" +
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
			Name:          name,
			BaseURL:       strings.TrimRight(provBaseURL, "/"),
			AuthHeader:    provAuthHeader,
			AuthScheme:    provAuthScheme,
			SessionHeader: provSessionHdr,
			Auth:          provAuth,
			External:      provExternal,
			Peer:          provPeer,
			CAFile:        provCAFile,
		}
		if provPeer {
			// The client's own credentials are forwarded: no stored key.
			if provAPIKey != "" || provAuthHeader != "" || provAuthScheme != "" || provExternal || provAuth == config.AuthPassthrough {
				return errors.New("--peer doesn't combine with --api-key, --auth-header, --auth-scheme, --external or --auth passthrough")
			}
			provNoAuth = true
		}
		if provCAFile != "" {
			if _, err := config.LoadCAPool(provCAFile); err != nil {
				return fmt.Errorf("--ca-file: %w", err)
			}
		}
		if provAuth != "" && provAuth != config.AuthManaged && provAuth != config.AuthPassthrough {
			return fmt.Errorf("--auth must be %s or %s", config.AuthManaged, config.AuthPassthrough)
		}
		if provAuth == config.AuthManaged {
			p.Auth = "" // the default; keep the YAML short
		}
		if provAuth == config.AuthPassthrough {
			// The client's own credentials are forwarded: no stored key.
			if provAPIKey != "" || provAuthHeader != "" || provAuthScheme != "" {
				return errors.New("--api-key, --auth-header and --auth-scheme don't apply with --auth passthrough")
			}
			provNoAuth = true
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
		fmt.Fprintln(cmd.OutOrStdout(), "Reference it from models[].targets[].provider; a running router reloads automatically.")
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
		fmt.Fprintln(tw, "NAME\tBASE URL\tAUTH\tFLAGS")
		for _, p := range provs {
			authDesc := "none"
			if k, _ := p["api_key"].(string); k != "" {
				authDesc = "encrypted"
				if !strings.HasPrefix(k, "enc:v1:") {
					authDesc = "PLAINTEXT (re-add with `provider add`)"
				}
			}
			var flags []string
			if b, _ := p["peer"].(bool); b {
				flags = append(flags, "peer")
				authDesc = "client's"
			}
			if b, _ := p["external"].(bool); b {
				flags = append(flags, "external")
			}
			if c, _ := p["ca_file"].(string); c != "" {
				flags = append(flags, "ca_file")
			}
			fmt.Fprintf(tw, "%v\t%v\t%s\t%s\n", p["name"], p["base_url"], authDesc, strings.Join(flags, ","))
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
	fmt.Printf("Removed %q from %s. A running router applies it automatically.\n", name, section)
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
	if err := verifyCipher(f, ci); err != nil {
		return nil, err
	}
	return ci, nil
}

// verifyCipher checks ci against master_key_check and the existing encrypted
// values. Errors wrap config.ErrWrongMasterKey.
func verifyCipher(f *configfile.File, ci *secrets.Cipher) error {
	if check := f.Scalar("master_key_check"); check != "" && !ci.VerifyKeyCheck(check) {
		return config.ErrWrongMasterKey
	}
	// Only authentication failures prove a wrong key; malformed placeholders are skipped.
	var bad error
	f.WalkScalars(func(n *yaml.Node) {
		if bad == nil && secrets.IsEncrypted(n.Value) {
			if _, err := ci.Decrypt(n.Value); errors.Is(err, secrets.ErrDecrypt) {
				bad = fmt.Errorf("%w (it cannot decrypt the value on line %d)", config.ErrWrongMasterKey, n.Line)
			}
		}
	})
	return bad
}

// interactiveCipher is masterCipher, but prompts for the master key (hidden)
// when none is configured and stdin is a terminal.
func interactiveCipher() (*secrets.Cipher, error) {
	key, err := interactiveMasterKey()
	if err != nil {
		return nil, err
	}
	return secrets.New(key)
}

// interactiveMasterKey is masterKey, falling back to a hidden prompt on a
// terminal when no key is set or the configured key file doesn't exist.
func interactiveMasterKey() (string, error) {
	key, err := masterKey()
	if !noKeyConfigured(err) || !stdinIsTerminal() {
		return key, err
	}
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "(master key file %s not found)\n", v.GetString("master_key_file"))
	}
	return readSecret(os.Stdin, "Master key: ")
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
	keyAddCmd.Flags().BoolVar(&keyNoExt, "disable-external", false, "never route the key's requests to external providers")
	keyAddCmd.Flags().StringSliceVar(&keyProvs, "providers", nil, "providers the key may reach directly at /provider/<name>/, comma separated; globs allowed (default: none)")
	keyCmd.AddCommand(keyAddCmd, keyListCmd, keyRemoveCmd)

	f := providerAddCmd.Flags()
	f.StringVar(&provBaseURL, "base-url", "", "OpenAI-compatible API base URL, e.g. https://api.openai.com/v1 (required)")
	f.StringVar(&provAPIKey, "api-key", "", "provider API key (prompted or read from stdin if omitted; note: flags end up in shell history)")
	f.BoolVar(&provNoAuth, "no-auth", false, "provider needs no API key")
	f.StringVar(&provAuthHeader, "auth-header", "", "header carrying the key (default Authorization)")
	f.StringVar(&provAuthScheme, "auth-scheme", "", "prefix before the key (default Bearer; \"none\" sends the raw key)")
	f.StringVar(&provAuth, "auth", "", "managed (default: clients use router keys, the router sends this provider's key) or passthrough (clients' own credentials forwarded unchecked, only at /provider/<name>/)")
	f.StringVar(&provSessionHdr, "session-header", "", "send a per-conversation id in this header (e.g. X-Opencode-Session for OpenCode Go)")
	f.BoolVar(&provExternal, "external", false, "provider outside this deployment (paid or remote API); skipped for requests forwarded by a peer router")
	f.BoolVar(&provPeer, "peer", false, "another simple-router: the client's credentials are forwarded, no API key (one hop, local targets only)")
	f.StringVar(&provCAFile, "ca-file", "", "PEM bundle trusted (only it) for this provider's HTTPS, e.g. a peer's self-signed certificate")
	_ = providerAddCmd.MarkFlagRequired("base-url")
	providerCmd.AddCommand(providerAddCmd, providerListCmd, providerRemoveCmd)
}
