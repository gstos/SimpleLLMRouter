// Package cmd implements the simple-router CLI.
package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

var v = viper.New()

var rootCmd = &cobra.Command{
	Use:           "simple-router",
	Version:       version,
	Short:         "An OpenRouter-compatible LLM router with priorities, failover and sticky routing",
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the CLI.
func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	return err
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringP("config", "c", "config.yaml", "path to the YAML config file (env SIMPLE_ROUTER_CONFIG)")
	pf.String("master-key", "", "base64 master key used to decrypt provider credentials (env SIMPLE_ROUTER_MASTER_KEY)")
	pf.String("master-key-file", "", "file containing the master key (env SIMPLE_ROUTER_MASTER_KEY_FILE)")
	_ = v.BindPFlag("config", pf.Lookup("config"))
	_ = v.BindPFlag("master_key", pf.Lookup("master-key"))
	_ = v.BindPFlag("master_key_file", pf.Lookup("master-key-file"))

	// Env overrides: SIMPLE_ROUTER_SERVER_LISTEN overrides server.listen, etc.
	v.SetEnvPrefix("SIMPLE_ROUTER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	rootCmd.AddCommand(serveCmd, keygenCmd, encryptCmd, apikeyCmd, healthCmd, validateCmd, pingCmd, keyCmd, providerCmd, initCmd, rotateCmd, unsealCmd, versionCmd)
}

// loadConfig reads, defaults and validates the config file (secrets stay encrypted).
func loadConfig() (*config.Config, error) {
	v.SetConfigFile(v.GetString("config"))
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg config.Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// loadDecryptedConfig loads the config and decrypts provider credentials.
func loadDecryptedConfig() (*config.Config, error) {
	ci, err := masterCipher()
	if err != nil {
		return nil, err
	}
	return loadDecryptedConfigWith(ci)
}

// loadDecryptedConfigWith loads the config and decrypts it with ci.
func loadDecryptedConfigWith(ci *secrets.Cipher) (*config.Config, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if err := cfg.DecryptSecrets(ci); err != nil {
		return nil, err
	}
	return cfg, nil
}

var errNoMasterKey = errors.New("master key required: set --master-key, --master-key-file, SIMPLE_ROUTER_MASTER_KEY or SIMPLE_ROUTER_MASTER_KEY_FILE")

// masterKey returns the master key from --master-key / SIMPLE_ROUTER_MASTER_KEY,
// else from the key file. A missing key file wraps fs.ErrNotExist.
func masterKey() (string, error) {
	key := v.GetString("master_key")
	if key == "" {
		if f := v.GetString("master_key_file"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return "", fmt.Errorf("reading master key file: %w", err)
			}
			key = string(b)
		}
	}
	if strings.TrimSpace(key) == "" {
		return "", errNoMasterKey
	}
	return key, nil
}

func masterCipher() (*secrets.Cipher, error) {
	key, err := masterKey()
	if err != nil {
		return nil, err
	}
	return secrets.New(key)
}

// noKeyConfigured reports whether err means "no master key available" (none
// set, or the configured file doesn't exist) rather than a bad key.
func noKeyConfigured(err error) bool {
	return errors.Is(err, errNoMasterKey) || errors.Is(err, fs.ErrNotExist)
}
