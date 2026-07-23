package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
)

type XSSResult struct {
	URL        string
	Payload    string
	Vulnerable bool
	Executed   bool // true if the payload ran as script (a JS dialog fired), not just reflected in the DOM
}

// ReflectedXSSAtURL loads rawURL with queryParam set to payload in a real (stealth-patched)
// Chrome tab and checks whether the payload executes. Using an actual browser instead of
// matching the raw HTTP response means the check reflects what a real visitor's browser would
// do: encoded output that a naive string search might miss as "safe" won't execute, and
// DOM-rewritten output that a raw body scan would miss as "safe" will still trigger the dialog.
// Any existing value for queryParam on rawURL is overwritten rather than duplicated, which is
// the correct behavior when testing a param discovered with an existing value (e.g. "?id=3").
func ReflectedXSSAtURL(browser *rod.Browser, rawURL, queryParam, payload string) (*XSSResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", rawURL, err)
	}
	q := u.Query()
	q.Set(queryParam, payload)
	u.RawQuery = q.Encode()
	target := u.String()

	page, err := stealth.Page(browser)
	if err != nil {
		return nil, err
	}
	defer page.Close()

	executed, err := navigateAndWatchForDialog(page, target)
	if err != nil {
		return nil, err
	}

	html, err := page.HTML()
	if err != nil {
		return nil, err
	}

	return &XSSResult{
		URL:        target,
		Payload:    payload,
		Executed:   executed,
		Vulnerable: executed || strings.Contains(html, payload),
	}, nil
}

// ReflectedXSS tests queryParam on host's root path "/" — kept for the existing reflected-xss
// CLI command's sake. Prefer ReflectedXSSAtURL for testing a param discovered on an arbitrary path.
func ReflectedXSS(browser *rod.Browser, host, queryParam, payload string) (*XSSResult, error) {
	return ReflectedXSSAtURL(browser, fmt.Sprintf("https://%s/", host), queryParam, payload)
}

type StoredXSSResult struct {
	FormURL    string
	VerifyURL  string
	Payload    string
	Verified   bool
	Executed   bool
	Vulnerable bool
}

// StoredXSS navigates to the page that hosts the target form, fills it out like a real user
// (so any CSRF token or client-side validation already on the page is handled for us by the
// browser instead of us having to scrape and replay it), submits it, then reloads the verify
// page to confirm whether the payload persisted and executes.
func StoredXSS(browser *rod.Browser, host, formPath, attackField, payload string, fields map[string]string, submitSelector, verifyPath string) (*StoredXSSResult, error) {
	result := &StoredXSSResult{
		FormURL: fmt.Sprintf("https://%s%s", host, formPath),
		Payload: payload,
	}

	page, err := stealth.Page(browser)
	if err != nil {
		return nil, err
	}
	defer page.Close()

	if err := page.Navigate(result.FormURL); err != nil {
		return nil, err
	}
	if err := page.WaitLoad(); err != nil {
		return nil, err
	}

	for name, value := range fields {
		el, err := page.Element(fmt.Sprintf(`[name=%q]`, name))
		if err != nil {
			return nil, fmt.Errorf("field %q not found: %w", name, err)
		}
		if err := el.Input(value); err != nil {
			return nil, err
		}
	}

	attackEl, err := page.Element(fmt.Sprintf(`[name=%q]`, attackField))
	if err != nil {
		return nil, fmt.Errorf("attack field %q not found: %w", attackField, err)
	}
	if err := attackEl.Input(payload); err != nil {
		return nil, err
	}

	if submitSelector != "" {
		submitEl, err := page.Element(submitSelector)
		if err != nil {
			return nil, fmt.Errorf("submit element %q not found: %w", submitSelector, err)
		}
		if err := submitEl.Click(proto.InputMouseButtonLeft, 1); err != nil {
			return nil, err
		}
	} else if _, err := attackEl.Eval(`() => this.form && this.form.requestSubmit()`); err != nil {
		return nil, err
	}

	if err := page.WaitStable(time.Second); err != nil {
		return nil, err
	}

	if verifyPath == "" {
		return result, nil
	}

	result.Verified = true
	result.VerifyURL = fmt.Sprintf("https://%s%s", host, verifyPath)

	executed, err := navigateAndWatchForDialog(page, result.VerifyURL)
	if err != nil {
		return result, fmt.Errorf("submit succeeded but verify navigation failed: %w", err)
	}

	html, err := page.HTML()
	if err != nil {
		return result, err
	}

	result.Executed = executed
	result.Vulnerable = executed || strings.Contains(html, payload)

	return result, nil
}

// navigateAndWatchForDialog navigates page to target while concurrently watching for a JS
// dialog (alert/confirm/prompt) triggered during load. A dialog blocks the page's "load" event
// until dismissed, so the watch has to run in its own goroutine alongside the navigation rather
// than after it. If no dialog appears within dialogTimeout, the wait naturally falls through with
// a zero-value event rather than blocking forever.
//
// The navigate+load itself gets its own, more generous bound (navTimeout): dialog detection and
// page loading are independent concerns, and without a separate bound here, a page that hangs for
// any non-dialog reason (a stuck resource load, an unresponsive backend call) would block forever
// on <-navErr once the dialog wait has already returned — this exact class of bug was found and
// fixed for the crawler's own navigation calls, and it applies here too since this helper backs
// every automatic reflected-xss check the crawler runs.
func navigateAndWatchForDialog(page *rod.Page, target string) (executed bool, err error) {
	const dialogTimeout = 10 * time.Second
	const navTimeout = 30 * time.Second

	dialogPage := page.Timeout(dialogTimeout)
	wait, handle := dialogPage.HandleDialog()

	navPage := page.Timeout(navTimeout)
	navErr := make(chan error, 1)
	go func() { navErr <- navPage.Navigate(target) }()

	dialog := wait()
	executed = dialog.Type != ""
	if executed {
		if hErr := handle(&proto.PageHandleJavaScriptDialog{Accept: true}); hErr != nil {
			return executed, hErr
		}
	}

	if err := <-navErr; err != nil {
		return executed, err
	}

	if err := navPage.WaitLoad(); err != nil {
		return executed, err
	}

	return executed, nil
}
