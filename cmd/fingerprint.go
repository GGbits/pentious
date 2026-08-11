package cmd

import (
	"fmt"
	"strings"

	"github.com/ggbits/pentious/internal/fingerprint"
	"github.com/spf13/cobra"
)

var (
	fingerprintHost string
	fingerprintPort int
)

var fingerprintCmd = &cobra.Command{
	Use:   "fingerprint",
	Short: "Fingerprint a web server via its HTTP response headers",
	Annotations: map[string]string{
		"skipBrowser": "true",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := fingerprint.Fingerprint(fingerprintHost, fingerprintPort, insecure)
		if err != nil {
			return err
		}

		server := result.Headers.Get("Server")

		fmt.Printf("URL:        %s\n", result.URL)
		if server != "" {
			fmt.Printf("Server:     %s\n", server)
			return nil
		}

		fmt.Printf("Server:     (not present)\n")
		fmt.Println()
		fmt.Println("No Server header on the normal response -- sending a malformed request to see how the server reports an error...")

		malformed, err := fingerprint.MalformedRequest(fingerprintHost, fingerprintPort, insecure)
		if err != nil {
			fmt.Printf("Malformed request probe failed: %v\n", err)
			return nil
		}
		malformed.NormalAltSvc = result.Headers.Get("Alt-Svc")

		fmt.Printf("Status:     %s\n", malformed.StatusLine)
		if errServer := malformed.Headers.Get("Server"); errServer != "" {
			fmt.Printf("Server:     %s\n", errServer)
		} else {
			fmt.Printf("Server:     (also not present)\n")
		}
		if body := strings.TrimSpace(malformed.Body); body != "" {
			fmt.Println("Body:")
			fmt.Println(body)
			if malformed.Truncated {
				fmt.Println("... [truncated]")
			}
		}

		fmt.Println()
		printSignatureMatches(malformed)

		return nil
	},
}

func init() {
	fingerprintCmd.Flags().StringVar(&fingerprintHost, "host", "", "target host (required)")
	fingerprintCmd.Flags().IntVar(&fingerprintPort, "port", 443, "target HTTPS port")
	fingerprintCmd.MarkFlagRequired("host")

	rootCmd.AddCommand(fingerprintCmd)
}

// printSignatureMatches scores the malformed-request probe response against every known server
// signature and prints each one's checklist, so the conclusion is traceable to the factors that
// drove it rather than just asserted.
func printSignatureMatches(malformed *fingerprint.MalformedResult) {
	matches := fingerprint.IdentifyServer(malformed)
	if len(matches) == 0 {
		return
	}

	fmt.Println("Signature matches:")
	for _, m := range matches {
		fmt.Printf("\n%s (%d/%d factors matched):\n", m.Signature, m.MatchedCount(), m.Total())
		for _, r := range m.Results {
			mark := "[ ]"
			if r.Matched {
				mark = "[x]"
			}
			fmt.Printf("  %s %s\n", mark, r.Name)
		}
	}

	best := matches[0]
	fmt.Println()
	if best.MatchedCount() == 0 {
		fmt.Println("Best guess:  none -- no known server signature matched")
		return
	}
	fmt.Printf("Best guess:  %s (%d/%d factors matched)\n", best.Signature, best.MatchedCount(), best.Total())
}
