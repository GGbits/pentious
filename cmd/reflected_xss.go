package cmd

import (
	"fmt"

	"github.com/ggbits/pentious/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	host        string
	queryString string
	useAlert    bool
)

var reflectedXSSCmd = &cobra.Command{
	Use:   "reflected-xss",
	Short: "Test for reflected XSS vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !useAlert {
			return fmt.Errorf("specify a payload flag (e.g. --alert)")
		}

		payload := `<script>alert(1)</script>`

		result, err := scanner.ReflectedXSS(browser, host, queryString, payload)
		if err != nil {
			return err
		}

		fmt.Printf("URL:        %s\n", result.URL)
		fmt.Printf("Payload:    %s\n", result.Payload)
		if result.Executed {
			fmt.Println("Result:     VULNERABLE — payload executed in the browser")
		} else if result.Vulnerable {
			fmt.Println("Result:     VULNERABLE — payload reflected unescaped")
		} else {
			fmt.Println("Result:     NOT VULNERABLE — payload not found, escaped, or did not execute")
		}

		return nil
	},
}

func init() {
	reflectedXSSCmd.Flags().StringVar(&host, "host", "", "target host (required)")
	reflectedXSSCmd.Flags().StringVar(&queryString, "query-string", "", "query parameter to inject into (required)")
	reflectedXSSCmd.Flags().BoolVar(&useAlert, "alert", false, "use alert(1) as the XSS payload")
	reflectedXSSCmd.MarkFlagRequired("host")
	reflectedXSSCmd.MarkFlagRequired("query-string")

	rootCmd.AddCommand(reflectedXSSCmd)
}
