package cmd

import (
	"crypto/tls"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var httpClient *http.Client

var rootCmd = &cobra.Command{
	Use:   "pentious",
	Short: "Web security testing tool",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
