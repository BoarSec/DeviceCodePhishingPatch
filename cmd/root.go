package cmd

import (
	"fmt"
	"github.com/denniskniep/DeviceCodePhishing/pkg/utils"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	noBanner bool
	verbose  bool
	version  = "1.1.0"
)

var rootCmd = &cobra.Command{
	Use:     "DeviceCodePhishing",
	Short:   "Phishing access-tokens with the Device Code Flow",
	Long:    `DeviceCodePhishing is an advanced phishing tool. It can be used for phishing access-tokens with the Device Code Flow.`,
	Version: version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		slog.SetDefault(logger)
		slog.SetLogLoggerLevel(slog.LevelInfo)

		if verbose {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}

		if !noBanner && cmd.Short != "Help about any command" && !strings.HasPrefix(cmd.Short, "Generate the autocompletion script for") {
			utils.PrintBanner(version)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&noBanner, "no-banner", false, "Do not display the banner")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
}
