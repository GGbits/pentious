package crawler

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/ggbits/pentious/internal/scanner"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
)

// navigationTimeout bounds every Navigate+WaitLoad pair in the crawler so a single
// unresponsive page (a slow backend call, a hung resource load, anything short of a JS dialog
// -- which startDialogAutoAccept handles separately) can't stall the whole crawl forever.
const navigationTimeout = 20 * time.Second

// logf prints scan progress/diagnostics to stderr. This is a CLI tool, not a library with
// multiple consumers, so a plain stderr print is simpler than threading a logger/callback
// through — and it's the only way to see what the login/crawl steps are actually doing when
// pointed at a real remote target that can't be inspected any other way.
func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[scan] "+format+"\n", args...)
}

const reflectedXSSPayload = `<script>alert(1)</script>`

type queueItem struct {
	url   *url.URL
	depth int
}

// Crawl discovers a web app's attack surface starting from opts.StartPath, cataloging pages,
// forms, and query parameters, and automatically running scanner.ReflectedXSSAtURL against
// every GET query parameter it finds. If creds is non-nil, it logs in first (via login) and
// crawls from the authenticated area; a definitive login failure is a fatal error. Per-page
// navigation failures are non-fatal and collected into CrawlResult.Errors instead — only setup
// failures (bad start URL, login failure) abort the whole crawl.
func Crawl(browser *rod.Browser, opts CrawlOptions, creds *Credentials) (*CrawlResult, error) {
	applyDefaults(&opts)

	base, err := url.Parse(fmt.Sprintf("https://%s%s", opts.Host, opts.StartPath))
	if err != nil {
		return nil, fmt.Errorf("invalid host/start-path: %w", err)
	}

	result := &CrawlResult{
		Host:        opts.Host,
		StartPath:   opts.StartPath,
		ScopePrefix: opts.ScopePrefix,
		MaxDepth:    opts.MaxDepth,
		MaxPages:    opts.MaxPages,
		StartedAt:   time.Now(),
	}

	page, err := stealth.Page(browser)
	if err != nil {
		return nil, err
	}
	defer page.Close()

	stopDialogHandler := startDialogAutoAccept(page)
	defer stopDialogHandler()

	seed := base
	if creds != nil {
		loginPath := opts.LoginPath
		if loginPath == "" {
			loginPath = opts.StartPath
		}
		loginURL, err := url.Parse(fmt.Sprintf("https://%s%s", opts.Host, loginPath))
		if err != nil {
			return nil, fmt.Errorf("invalid login path: %w", err)
		}

		logf("navigating to login page: %s", loginURL.String())
		if err := navigateWithTimeout(page, loginURL.String()); err != nil {
			return nil, fmt.Errorf("could not load login page: %w", err)
		}
		settleAfterLoad(page)
		if landed, err := page.Info(); err == nil {
			logf("login page loaded, landed on: %s", landed.URL)
		}

		if err := login(page, creds); err != nil {
			return nil, err
		}
		logf("login verified for user %q", creds.Username)

		result.Authenticated = true
		result.Username = creds.Username

		postLoginPath := opts.PostLoginPath
		if postLoginPath == "" {
			postLoginPath = opts.ScopePrefix
		}
		seed, err = url.Parse(fmt.Sprintf("https://%s%s", opts.Host, postLoginPath))
		if err != nil {
			return nil, fmt.Errorf("invalid post-login path: %w", err)
		}
		logf("crawling from: %s", seed.String())
	}

	crawlLoop(browser, page, base, seed, opts, result)

	result.FinishedAt = time.Now()
	return result, nil
}

// settleAfterLoad gives a JS-rendered page a chance to finish fetching/mounting its real content
// before extraction runs. page.WaitLoad only guarantees the initial document's load event fired
// — it says nothing about client-side rendering (SPA-style frameworks commonly fetch data via
// XHR/fetch and mount content afterward) or a client-side redirect that fires after the initial
// page already loaded (e.g. an app that checks auth state in JS before routing to a landing
// page).
//
// The fixed baseline sleep matters: WaitStable measures whether the DOM has been quiet for its
// window, counting from whenever it's called — it can't distinguish "already finished rendering"
// from "hasn't started mutating yet." A page whose real content only appears after a short delay
// (a timer, or a fetch that hasn't resolved yet) looks perfectly "stable" the instant WaitStable
// is called, before that content ever shows up. The baseline sleep gives that initial render
// window a chance to happen before the bounded checks below even start looking.
//
// Both bounded waits are deliberately capped and best-effort: this may be a VMS-style app where a
// dashboard page never goes fully network-idle or stops mutating the DOM (live video, polling),
// and that's expected — we proceed with whatever's rendered once the cap is hit rather than
// stalling the crawl on a page that will never go quiet.
func settleAfterLoad(page *rod.Page) {
	time.Sleep(time.Second)
	_ = page.Timeout(4 * time.Second).WaitIdle(500 * time.Millisecond)
	_ = page.Timeout(2 * time.Second).WaitStable(300 * time.Millisecond)
}

// navigateWithTimeout navigates to target and waits for it to load, bounded by navigationTimeout
// so an unresponsive page can't block the crawl forever. Both steps share one timeout window
// rather than getting navigationTimeout each, so the combined operation is what's actually bounded.
func navigateWithTimeout(page *rod.Page, target string) error {
	timedPage := page.Timeout(navigationTimeout)
	if err := timedPage.Navigate(target); err != nil {
		return err
	}
	return timedPage.WaitLoad()
}

// startDialogAutoAccept auto-accepts any JS dialog (alert/confirm/prompt, and critically
// beforeunload) that appears on page for as long as the returned stop function hasn't been
// called. Without this, a page that registers a beforeunload handler -- common for
// setup/wizard-style pages warning about unsaved changes -- would silently block every
// subsequent Navigate/WaitLoad on this page forever the moment the crawl tries to leave it,
// since nothing else here ever dismisses that prompt.
func startDialogAutoAccept(page *rod.Page) (stop func()) {
	ctx, cancel := context.WithCancel(page.GetContext())
	dialogPage := page.Context(ctx)

	go func() {
		dialogPage.EachEvent(func(e *proto.PageJavascriptDialogOpening) bool {
			_ = proto.PageHandleJavaScriptDialog{Accept: true}.Call(dialogPage)
			return false // keep listening for the next dialog
		})()
	}()

	return cancel
}

func applyDefaults(opts *CrawlOptions) {
	if opts.StartPath == "" {
		opts.StartPath = "/"
	}
	if opts.ScopePrefix == "" {
		opts.ScopePrefix = defaultScopePrefix(opts.StartPath)
	}
	if opts.MaxDepth == 0 {
		opts.MaxDepth = 5
	}
	if opts.MaxPages == 0 {
		opts.MaxPages = 200
	}
	if opts.MaxQueryVariantsPerPath == 0 {
		opts.MaxQueryVariantsPerPath = 3
	}
	if opts.Politeness == 0 {
		opts.Politeness = 500 * time.Millisecond
	}
	if opts.MaxClickCandidates == 0 {
		opts.MaxClickCandidates = 30
	}
}

func crawlLoop(browser *rod.Browser, page *rod.Page, base, seed *url.URL, opts CrawlOptions, result *CrawlResult) {
	visited := map[string]bool{}
	queryVariantCounts := map[string]int{}
	excludeRules := parseExcludeRules(opts.Exclude)
	// clickTried is crawl-wide, not per-page: a persistent nav/sidebar (the common case) repeats
	// the same candidates on every page, and without a shared set the crawler would re-click
	// "Home", "Settings", etc. from scratch on every single page it visits.
	clickTried := map[string]bool{}
	queue := []queueItem{{url: seed, depth: 0}}

	for len(queue) > 0 && len(result.PagesVisited) < opts.MaxPages {
		item := queue[0]
		queue = queue[1:]

		key := normalize(item.url)
		if visited[key] {
			continue
		}
		visited[key] = true

		time.Sleep(opts.Politeness)

		logf("visiting (depth %d): %s", item.depth, item.url.String())

		if err := navigateWithTimeout(page, item.url.String()); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("navigate to %s failed: %v", item.url, err))
			continue
		}
		logf("loaded, settling: %s", item.url.String())
		settleAfterLoad(page)

		info, err := page.Info()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("read page info for %s failed: %v", item.url, err))
			continue
		}
		logf("settled, landed on: %s", info.URL)
		// The page actually rendered (info.URL) can differ from what we asked for (item.url) —
		// a server-side redirect, or a client-side one fired after WaitLoad already returned
		// (common for an app that checks auth state in JS before routing). Everything from here
		// on uses the real landed URL: it's what the DOM's relative links/forms actually resolve
		// against, and reporting item.url instead would mislabel the page and could misresolve
		// relative hrefs found on it.
		landedURL, err := url.Parse(info.URL)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("parse landed URL %q failed: %v", info.URL, err))
			continue
		}
		if landedKey := normalize(landedURL); landedKey != key {
			if visited[landedKey] {
				continue // this redirect target was already fully processed via another link
			}
			visited[landedKey] = true
		}

		result.PagesVisited = append(result.PagesVisited, PageVisit{URL: landedURL.String(), Depth: item.depth, Title: info.Title})

		logf("testing query params on: %s", landedURL.String())
		testQueryParams(browser, landedURL, result)

		logf("extracting forms/links on: %s", landedURL.String())
		if forms, err := extractForms(page, landedURL); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("extract forms on %s failed: %v", landedURL, err))
		} else {
			result.Forms = append(result.Forms, forms...)
			// opts.FuzzForms is always false in v1 (forms are never filled/submitted here) —
			// this is the seam a future --fuzz-forms mode would hook into per discovered form.
		}

		links, err := extractLinks(page, landedURL)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("extract links on %s failed: %v", landedURL, err))
			continue
		}

		if item.depth >= opts.MaxDepth {
			continue
		}

		for _, link := range links {
			if isDestructiveLink(link.URL.String(), link.Text) {
				continue
			}
			if isInScopeForCrawl(base, opts, link.URL, queryVariantCounts, excludeRules) {
				queue = append(queue, queueItem{url: link.URL, depth: item.depth + 1})
			}
		}

		if opts.ClickNav {
			logf("click-nav discovery starting on: %s", landedURL.String())
			queue = append(queue, discoverClickNav(page, landedURL, base, opts, item.depth, queryVariantCounts, clickTried, excludeRules, result)...)
			logf("click-nav discovery done on: %s", landedURL.String())
		}
	}
}

// testQueryParams catalogs and reflected-xss-tests every query parameter found on pageURL,
// using a fresh tab (sharing the same authenticated browser session) so the injected
// navigation/reload doesn't disturb the crawl page's current position.
func testQueryParams(browser *rod.Browser, pageURL *url.URL, result *CrawlResult) {
	pathOnly := pageURL.Path
	for _, param := range extractQueryParams(pageURL) {
		result.QueryParams = append(result.QueryParams, QueryParamInfo{
			PageURL: pageURL.String(),
			Path:    pathOnly,
			Param:   param,
		})

		logf("reflected-xss check: param %q on %s", param, pageURL.String())
		xssResult, err := scanner.ReflectedXSSAtURL(browser, pageURL.String(), param, reflectedXSSPayload)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("reflected-xss check for %s on %s failed: %v", param, pageURL, err))
			continue
		}
		logf("reflected-xss check done: param %q (vulnerable=%v)", param, xssResult.Vulnerable)

		result.Findings = append(result.Findings, Finding{
			Kind:       "reflected-xss",
			URL:        xssResult.URL,
			Param:      param,
			Payload:    xssResult.Payload,
			Executed:   xssResult.Executed,
			Vulnerable: xssResult.Vulnerable,
		})
	}
}
