package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Set at build time with -ldflags "-X github.com/gstos/SimpleLLMRouter/cmd.version=...".
var (
	version = "dev"
	commit  = "none"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "simple-router %s (commit %s, %s, %s/%s)\n", version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	},
}
