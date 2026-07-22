package cmd

import (
	"os"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/spf13/cobra"
)

var (
	browser  *rod.Browser
	headless bool
	insecure bool
)

var rootCmd = &cobra.Command{
	Use:   "pentious",
	Short: "Web security testing tool",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		l := launcher.New().Headless(headless).Leakless(false)
		if insecure {
			l = l.Set("ignore-certificate-errors")
		}

		controlURL := l.MustLaunch()

		browser = rod.New().ControlURL(controlURL).MustConnect()
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if browser != nil {
			browser.MustClose()
		}
	},
}

func Execute() {
	rootCmd.PersistentFlags().BoolVar(&headless, "headless", true, "run Chrome headless")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", true, "ignore TLS certificate errors (self-signed certs, etc.)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
