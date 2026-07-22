package cmd

import (
	"fmt"
	"strings"

	"github.com/ggbits/pentious/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	storedFormPath       string
	storedAttackField    string
	storedFields         []string
	storedSubmitSelector string
	storedVerifyPath     string
	storedUseAlert       bool
)

var storedXSSCmd = &cobra.Command{
	Use:   "stored-xss",
	Short: "Test for stored XSS vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !storedUseAlert {
			return fmt.Errorf("specify a payload flag (e.g. --alert)")
		}

		fields := map[string]string{}
		for _, f := range storedFields {
			name, value, ok := strings.Cut(f, "=")
			if !ok {
				return fmt.Errorf("invalid --field %q, expected name=value", f)
			}
			fields[name] = value
		}

		payload := `<script>alert(1)</script>`

		result, err := scanner.StoredXSS(browser, host, storedFormPath, storedAttackField, payload, fields, storedSubmitSelector, storedVerifyPath)
		if err != nil {
			return err
		}

		fmt.Printf("Form URL:   %s\n", result.FormURL)
		fmt.Printf("Payload:    %s\n", result.Payload)
		if result.Verified {
			fmt.Printf("Verify URL: %s\n", result.VerifyURL)
		}
		if result.Executed {
			fmt.Println("Result:     VULNERABLE — payload executed in the browser")
		} else if result.Vulnerable {
			fmt.Println("Result:     VULNERABLE — payload reflected unescaped")
		} else if result.Verified {
			fmt.Println("Result:     NOT VULNERABLE — payload not found, escaped, or did not execute")
		} else {
			fmt.Println("Result:     UNKNOWN — no --verify-path given, submission was not checked")
		}

		return nil
	},
}

func init() {
	storedXSSCmd.Flags().StringVar(&host, "host", "", "target host (required)")
	storedXSSCmd.Flags().StringVar(&storedFormPath, "form-path", "", "path of the page hosting the form (required)")
	storedXSSCmd.Flags().StringVar(&storedAttackField, "attack-field", "", "name attribute of the field to inject the payload into (required)")
	storedXSSCmd.Flags().StringArrayVar(&storedFields, "field", nil, "other form field to fill, as name=value (repeatable)")
	storedXSSCmd.Flags().StringVar(&storedSubmitSelector, "submit-selector", "", "CSS selector for the submit button (defaults to calling form.requestSubmit() on the attack field's form)")
	storedXSSCmd.Flags().StringVar(&storedVerifyPath, "verify-path", "", "path to reload after submission to check whether the payload persisted")
	storedXSSCmd.Flags().BoolVar(&storedUseAlert, "alert", false, "use alert(1) as the XSS payload")
	storedXSSCmd.MarkFlagRequired("host")
	storedXSSCmd.MarkFlagRequired("form-path")
	storedXSSCmd.MarkFlagRequired("attack-field")

	rootCmd.AddCommand(storedXSSCmd)
}
