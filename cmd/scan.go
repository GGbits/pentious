package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ggbits/pentious/internal/crawler"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	scanHost               string
	scanStartPath          string
	scanScopePrefix        string
	scanMaxDepth           int
	scanMaxPages           int
	scanPoliteness         time.Duration
	scanMaxQueryVariants   int
	scanClickNav           bool
	scanMaxClickCandidates int
	scanExclude            []string

	scanUsername            string
	scanPassword            string
	scanPasswordStdin       bool
	scanUsernameSelector    string
	scanPasswordSelector    string
	scanLoginSubmitSelector string
	scanLoginPath           string

	scanReportPath string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Crawl a web app, catalog its attack surface, and test discovered query parameters for reflected XSS",
	RunE: func(cmd *cobra.Command, args []string) error {
		creds, err := resolveCredentials()
		if err != nil {
			return err
		}

		opts := crawler.CrawlOptions{
			Host:                    scanHost,
			StartPath:               scanStartPath,
			ScopePrefix:             scanScopePrefix,
			MaxDepth:                scanMaxDepth,
			MaxPages:                scanMaxPages,
			Politeness:              scanPoliteness,
			MaxQueryVariantsPerPath: scanMaxQueryVariants,
			ClickNav:                scanClickNav,
			MaxClickCandidates:      scanMaxClickCandidates,
			Exclude:                 scanExclude,
			LoginPath:               scanLoginPath,
		}

		mode := "unauthenticated"
		if creds != nil {
			mode = fmt.Sprintf("authenticated (user: %s)", creds.Username)
		}
		fmt.Printf("Starting %s scan of https://%s%s ...\n", mode, scanHost, scanStartPath)

		result, err := crawler.Crawl(browser, opts, creds)
		if err != nil {
			return err
		}

		reportPath := scanReportPath
		if reportPath == "" {
			reportPath = fmt.Sprintf("pentious-scan-%s.md", time.Now().Format("20060102-150405"))
		}
		if err := os.WriteFile(reportPath, []byte(crawler.RenderMarkdown(result)), 0644); err != nil {
			return err
		}

		vulnerable := 0
		for _, f := range result.Findings {
			if f.Vulnerable {
				vulnerable++
			}
		}

		fmt.Printf("Pages visited: %d   Forms found: %d   Query params found: %d\n",
			len(result.PagesVisited), len(result.Forms), len(result.QueryParams))
		fmt.Printf("Findings: %d vulnerable / %d tested\n", vulnerable, len(result.Findings))
		fmt.Printf("Report written to %s\n", reportPath)

		return nil
	},
}

// resolveCredentials resolves login credentials in priority order: --password-stdin, then the
// --password flag, then (if --username was given and neither of those was) an interactive
// hidden prompt. Returns nil (unauthenticated mode) if --username was never given. The password
// never touches any package-level or longer-lived variable — it's returned directly inside a
// *crawler.Credentials that the caller passes straight into crawler.Crawl.
func resolveCredentials() (*crawler.Credentials, error) {
	if scanUsername == "" {
		return nil, nil
	}

	var password string
	switch {
	case scanPasswordStdin:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading password from stdin: %w", err)
		}
		password = strings.TrimRight(string(data), "\r\n")
	case scanPassword != "":
		password = scanPassword
	case term.IsTerminal(int(os.Stdin.Fd())):
		fmt.Fprint(os.Stderr, "Password: ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("reading password from prompt: %w", err)
		}
		password = string(pw)
		for i := range pw {
			pw[i] = 0
		}
	default:
		// Not a real terminal from term's point of view — notably Git Bash/MinTTY on Windows,
		// which doesn't expose a native console handle, so term.IsTerminal/ReadPassword can't
		// work there even in an interactive session. Fall back to a plain, visible read rather
		// than hard-failing; --password-stdin remains the way to keep the value off the screen
		// in that environment.
		fmt.Fprintln(os.Stderr, "Password (visible - not a detected terminal; use --password-stdin to avoid echoing):")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("reading password from stdin: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
	}

	if password == "" {
		return nil, fmt.Errorf("--username given but no password provided (use --password, --password-stdin, or omit --password to be prompted)")
	}

	return &crawler.Credentials{
		Username:            scanUsername,
		Password:            password,
		UsernameSelector:    scanUsernameSelector,
		PasswordSelector:    scanPasswordSelector,
		LoginSubmitSelector: scanLoginSubmitSelector,
	}, nil
}

func init() {
	scanCmd.Flags().StringVar(&scanHost, "host", "", "target host (required)")
	scanCmd.Flags().StringVar(&scanStartPath, "start-path", "/", "path to begin crawling from")
	scanCmd.Flags().StringVar(&scanScopePrefix, "scope-prefix", "", "path prefix to restrict crawling to (defaults to the directory of --start-path)")
	scanCmd.Flags().IntVar(&scanMaxDepth, "max-depth", 5, "maximum link-following depth")
	scanCmd.Flags().IntVar(&scanMaxPages, "max-pages", 200, "maximum total pages to visit")
	scanCmd.Flags().DurationVar(&scanPoliteness, "politeness-delay", 500*time.Millisecond, "delay between page navigations")
	scanCmd.Flags().IntVar(&scanMaxQueryVariants, "max-query-variants", 3, "max distinct query-string variants of the same path to crawl (e.g. ?id=1, ?id=2, ...)")
	scanCmd.Flags().BoolVar(&scanClickNav, "click-nav", false, "also discover pages via clicking JS-only nav items with no real href (interacts with UI elements -- off by default)")
	scanCmd.Flags().StringArrayVar(&scanExclude, "exclude", nil, "path (optionally with a required query key, e.g. /vmsportal/login?logout) to never crawl to; repeatable")
	scanCmd.Flags().IntVar(&scanMaxClickCandidates, "max-click-candidates", 30, "per-page cap on how many click-nav candidates to try (only used with --click-nav)")

	scanCmd.Flags().StringVar(&scanUsername, "username", "", "login username (enables authenticated scan mode)")
	scanCmd.Flags().StringVar(&scanPassword, "password", "", "login password -- visible in shell history/process listings; prefer --password-stdin, or leave unset to be prompted")
	scanCmd.Flags().BoolVar(&scanPasswordStdin, "password-stdin", false, "read the login password from stdin (for scripting/CI)")
	scanCmd.Flags().StringVar(&scanUsernameSelector, "username-selector", "", "CSS selector for the username field (optional; auto-detected if empty)")
	scanCmd.Flags().StringVar(&scanPasswordSelector, "password-selector", "", "CSS selector for the password field (optional; auto-detected if empty)")
	scanCmd.Flags().StringVar(&scanLoginSubmitSelector, "login-submit-selector", "", "CSS selector for the login submit button (optional; falls back to form.requestSubmit())")
	scanCmd.Flags().StringVar(&scanLoginPath, "login-path", "", "path of the login page, if different from --start-path")

	scanCmd.Flags().StringVar(&scanReportPath, "report", "", "path to write the Markdown report to (defaults to pentious-scan-<timestamp>.md)")
	scanCmd.MarkFlagRequired("host")

	rootCmd.AddCommand(scanCmd)
}
