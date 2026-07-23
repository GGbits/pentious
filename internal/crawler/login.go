package crawler

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// login drives a real login form on page (already navigated to the login page) using creds,
// following the same "explicit selector override, sensible fallback" pattern as the existing
// stored-xss command. It returns an error if login cannot be confirmed successful, so an
// authenticated crawl never silently proceeds as an anonymous session.
//
// Cookies/session persist automatically across every subsequent page opened from the same
// non-incognito *rod.Browser (CDP cookie state lives at the browser-profile level), so nothing
// here or in the caller needs to manually extract or inject cookies.
func login(page *rod.Page, creds *Credentials) error {
	preLoginInfo, err := page.Info()
	if err != nil {
		return err
	}
	preLoginPath := pathOf(preLoginInfo.URL)

	passwordEl, err := findPasswordField(page, creds.PasswordSelector)
	if err != nil {
		return fmt.Errorf("could not locate password field: %w", err)
	}
	logf("password field: %s", describeElement(passwordEl))

	usernameEl, err := findUsernameField(page, creds.UsernameSelector)
	if err != nil {
		return fmt.Errorf("could not locate username field: %w", err)
	}
	logf("username field: %s", describeElement(usernameEl))

	if err := usernameEl.Input(creds.Username); err != nil {
		return err
	}
	if err := passwordEl.Input(creds.Password); err != nil {
		return err
	}

	if err := submitLoginForm(page, passwordEl, creds.LoginSubmitSelector); err != nil {
		return fmt.Errorf("could not submit login form: %w", err)
	}
	logf("login form submitted, waiting for the page to settle")
	// Best-effort only: some apps fetch user/session data via AJAX before swapping in the
	// post-login view, so give that a moment, but don't treat a timeout here as login failure —
	// verifyLoginSuccess makes the actual pass/fail call based on DOM state, not on whether the
	// page ever went fully quiet (a live-updating dashboard might never do that).
	settleAfterLoad(page)

	return verifyLoginSuccess(page, preLoginPath, creds.Username)
}

// findPasswordField applies the selector override if given, else falls back to
// input[type=password] — a near-certain heuristic since real HTML login forms mark password
// fields this way essentially always.
func findPasswordField(page *rod.Page, selector string) (*rod.Element, error) {
	if selector != "" {
		return page.Element(selector)
	}
	return page.Element(`input[type="password"]`)
}

// findUsernameField applies the selector override if given, else looks at visible
// text/email/untyped inputs (which naturally excludes the password field, since that always
// carries type="password"), tie-breaking on name/id/autocomplete hints if more than one exists.
func findUsernameField(page *rod.Page, selector string) (*rod.Element, error) {
	if selector != "" {
		return page.Element(selector)
	}

	candidates, err := page.Elements(`input[type="text"], input[type="email"], input:not([type])`)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no username-like input field found (specify --username-selector)")
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}

	hints := []string{"user", "email", "login"}
	for _, el := range candidates {
		for _, attr := range []string{"name", "id", "autocomplete"} {
			v, err := el.Attribute(attr)
			if err != nil || v == nil {
				continue
			}
			lv := strings.ToLower(*v)
			for _, h := range hints {
				if strings.Contains(lv, h) {
					return el, nil
				}
			}
		}
	}
	return candidates[0], nil
}

// submitLoginForm clicks the selector override if given; otherwise looks for a submit
// button/input inside the password field's containing form, falling back to JS
// form.requestSubmit() on the password element — the same fallback StoredXSS already uses.
func submitLoginForm(page *rod.Page, passwordEl *rod.Element, selector string) error {
	if selector != "" {
		el, err := page.Element(selector)
		if err != nil {
			return fmt.Errorf("submit element %q not found: %w", selector, err)
		}
		return el.Click(proto.InputMouseButtonLeft, 1)
	}

	if formObj, err := passwordEl.Eval(`() => this.form`); err == nil {
		if formEl, err := page.ElementFromObject(formObj); err == nil {
			if submitEl, err := formEl.Element(`button[type="submit"], input[type="submit"], button:not([type])`); err == nil {
				return submitEl.Click(proto.InputMouseButtonLeft, 1)
			}
		}
	}

	_, err := passwordEl.Eval(`() => this.form && this.form.requestSubmit()`)
	return err
}

// verifyLoginSuccess's hard gate is: no input[type=password] remains present anywhere on the
// page after submit. That alone is deliberately strict — a classic multi-page app that rejects
// bad credentials conventionally re-renders the login form (password field included), so its
// absence is a reliable success signal. A false "login failed" is cheap to notice and retry,
// whereas a false "login succeeded" would silently poison an entire scan's worth of findings by
// mislabeling an anonymous crawl as authenticated.
//
// The page path is deliberately NOT part of the hard gate: some apps (particularly single-page
// apps, which is plausible for a Java-frontend admin portal) authenticate and swap rendered
// content client-side without ever changing the URL path, so requiring the path to change would
// misreport a real, successful login as a failure on exactly that class of app.
func verifyLoginSuccess(page *rod.Page, preLoginPath, username string) error {
	info, err := page.Info()
	if err != nil {
		return err
	}
	postLoginPath := pathOf(info.URL)

	stillHasPassword, _, err := page.Has(`input[type="password"]`)
	if err != nil {
		return err
	}
	if stillHasPassword {
		note := ""
		if postLoginPath == preLoginPath {
			note = " (still on the login page's path)"
		}
		return fmt.Errorf("login failed for user %q: a password field is still present after submit%s — check credentials or --username-selector/--password-selector/--login-submit-selector", username, note)
	}

	return nil
}

// pathOf extracts the path component of a URL string, tolerating parse failure by returning the
// input unchanged (only used for a same-path comparison, never for navigation).
func pathOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Path
	}
	return rawURL
}

// describeElement gives a short, non-sensitive identifier for a field (name/id/type), purely
// for login diagnostics — never includes a field's value, so it's safe to log.
func describeElement(el *rod.Element) string {
	name, _ := el.Attribute("name")
	id, _ := el.Attribute("id")
	typ, _ := el.Attribute("type")

	parts := []string{}
	if name != nil && *name != "" {
		parts = append(parts, fmt.Sprintf("name=%q", *name))
	}
	if id != nil && *id != "" {
		parts = append(parts, fmt.Sprintf("id=%q", *id))
	}
	if typ != nil && *typ != "" {
		parts = append(parts, fmt.Sprintf("type=%q", *typ))
	}
	if len(parts) == 0 {
		return "(no name/id/type attribute)"
	}
	return strings.Join(parts, " ")
}
