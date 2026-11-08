package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/configfile"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

var dnsEnvPath = []string{"server", "tls", "acme", "dns_env"}

var acmeCmd = &cobra.Command{
	Use:   "acme",
	Short: "Manage TLS mode acme (lego) settings",
}

var acmeEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Manage the DNS provider variables passed to lego (server.tls.acme.dns_env)",
}

var (
	acmeEnvValue string
	acmeEnvPlain bool
)

var acmeEnvSetCmd = &cobra.Command{
	Use:   "set <NAME>",
	Short: "Set a DNS provider variable, encrypted with the master key by default",
	Long: "Set a variable for lego's DNS provider, e.g. CLOUDFLARE_DNS_API_TOKEN (see `lego dnshelp -c <provider>`\n" +
		"for the names). The value is encrypted with the master key unless --plain is given (for\n" +
		"non-secret settings like AWS_REGION). Without --value it is read from piped stdin or a hidden\n" +
		"prompt. LEGO_*, loader and shell variables are refused.\n\n" +
		"  simple-router acme env set CLOUDFLARE_DNS_API_TOKEN\n" +
		"  simple-router acme env set AWS_REGION --plain --value eu-west-1",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.ToUpper(args[0])
		if err := config.CheckLegoEnvName(name); err != nil {
			return err
		}
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		var ci *secrets.Cipher
		if !acmeEnvPlain {
			if ci, err = verifiedCipher(f); err != nil { // verify before asking for the value
				return err
			}
		}
		val := acmeEnvValue
		if val == "" {
			if val, err = readSecret(cmd.InOrStdin(), name+": "); err != nil {
				return err
			}
		}
		if val == "" {
			return errors.New("empty value")
		}
		if ci != nil {
			if f.Scalar("master_key_check") == "" {
				f.SetScalar("master_key_check", ci.KeyCheck(), keyCheckComment)
			}
			if val, err = ci.Encrypt(val); err != nil {
				return err
			}
		}
		f.SetIn(dnsEnvPath, name, val)
		if err := f.Save(); err != nil {
			return err
		}
		state := "encrypted"
		if acmeEnvPlain {
			state = "plain text"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Set %s (%s). A running router uses it on its next lego run (SIGHUP runs it now).\n", name, state)
		return nil
	},
}

var acmeEnvListCmd = &cobra.Command{
	Use:   "list",
	Short: "List DNS provider variables (values of encrypted ones are not shown)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		kv := f.KeysIn(dnsEnvPath...)
		sort.Slice(kv, func(i, j int) bool { return kv[i][0] < kv[j][0] })
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tVALUE")
		for _, e := range kv {
			val := e[1]
			if secrets.IsEncrypted(val) {
				val = "(encrypted)"
			}
			fmt.Fprintf(tw, "%s\t%s\n", e[0], val)
		}
		return tw.Flush()
	},
}

var acmeEnvRemoveCmd = &cobra.Command{
	Use:   "remove <NAME>",
	Short: "Remove a DNS provider variable",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := configfile.Load(v.GetString("config"))
		if err != nil {
			return err
		}
		name := strings.ToUpper(args[0])
		if !f.RemoveIn(dnsEnvPath, name) {
			return fmt.Errorf("%s is not set", name)
		}
		if err := f.Save(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Removed %s.\n", name)
		return nil
	},
}

func init() {
	acmeEnvSetCmd.Flags().StringVar(&acmeEnvValue, "value", "", "the value (prompted or read from stdin if omitted; flags end up in shell history)")
	acmeEnvSetCmd.Flags().BoolVar(&acmeEnvPlain, "plain", false, "store in plain text (non-secret settings only)")
	acmeEnvCmd.AddCommand(acmeEnvSetCmd, acmeEnvListCmd, acmeEnvRemoveCmd)
	acmeCmd.AddCommand(acmeEnvCmd)
}
