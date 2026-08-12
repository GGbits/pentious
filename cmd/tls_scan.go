package cmd

import (
	"fmt"
	"net"

	"github.com/ggbits/pentious/internal/tlsscan"
	"github.com/spf13/cobra"
)

var (
	tlsScanHost string
	tlsScanPort int
)

var tlsScanCmd = &cobra.Command{
	Use:   "tls-scan",
	Short: "Enumerate which TLS protocol versions and cipher suites a server accepts",
	Annotations: map[string]string{
		"skipBrowser": "true",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := tlsscan.Scan(tlsScanHost, tlsScanPort, insecure)
		if err != nil {
			return err
		}

		printTLSScanResult(result)

		return nil
	},
}

func init() {
	tlsScanCmd.Flags().StringVar(&tlsScanHost, "host", "", "target host (required)")
	tlsScanCmd.Flags().IntVar(&tlsScanPort, "port", 443, "target HTTPS port")
	tlsScanCmd.MarkFlagRequired("host")

	rootCmd.AddCommand(tlsScanCmd)
}

// printTLSScanResult prints one section per TLS version, each a table of the ciphers probed for
// that version. Column width is derived from the longest cipher name actually being printed
// rather than a fixed literal, since cipher suite names vary too widely in length for that.
func printTLSScanResult(result *tlsscan.Result) {
	fmt.Printf("Host: %s\n", net.JoinHostPort(result.Host, fmt.Sprint(result.Port)))
	fmt.Println()

	for _, v := range result.Versions {
		label := v.VersionName
		if v.Deprecated {
			label += " (deprecated)"
		}

		if !v.Supported {
			fmt.Printf("%s: not supported\n\n", label)
			continue
		}

		fmt.Printf("%s: supported\n", label)

		nameWidth := 0
		for _, c := range v.Ciphers {
			if len(c.CipherName) > nameWidth {
				nameWidth = len(c.CipherName)
			}
		}

		for _, c := range v.Ciphers {
			status := "not supported"
			if c.Supported {
				status = "supported"
				if c.Insecure {
					status = "supported [WEAK]"
				}
			}
			fmt.Printf("  %-*s  %s\n", nameWidth, c.CipherName, status)
		}
		fmt.Println()
	}
}
