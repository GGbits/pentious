package crawler

import (
	"net/url"
	"strings"
	"time"

	"github.com/go-rod/rod"
)

// clickCandidatesJS finds elements that look clickable-and-meaningful without relying on an
// attached event listener: modern frontend frameworks (React in particular) commonly route all
// clicks through one delegated listener at the app's root rather than attaching a listener to
// each nav item individually, so checking "does this specific element have a click listener"
// (via CDP's DOMDebugger.getEventListeners) does not reliably find per-item handlers.
//
// Candidates are deliberately restricted to descendants of a recognizable nav/menu/sidebar
// container (a <nav> tag, role="navigation", or a class name containing "nav"/"menu"/"sidebar"),
// and anything inside a <form> anywhere is excluded outright. This is a hard lesson from testing
// against a real app: an earlier, unrestricted version of this heuristic (cursor:pointer +
// non-trivial text, searched across the whole page) walked straight into an in-page rule-creation
// wizard and started selecting dropdown options and clicking Save, because a dropdown option and
// a Save button look exactly like a nav item to a heuristic that only looks at cursor style and
// text. Restricting to known nav containers is narrower — a nav item that lives outside such a
// container won't be found — but it structurally can't wander into page content the way the
// unrestricted version did, which matters far more given this interacts with a live device.
const clickCandidatesJS = `() => {
	const containerSelector = 'nav, [role="navigation"], [class*="nav" i], [class*="menu" i], [class*="sidebar" i]';
	const containers = document.querySelectorAll(containerSelector);

	const seen = new Set();
	const out = [];
	for (const container of containers) {
		if (container.closest('form')) continue;

		for (const el of container.querySelectorAll('*')) {
			if (seen.has(el)) continue;
			if (el.closest('form')) continue;

			const style = getComputedStyle(el);
			if (style.cursor !== 'pointer') continue;
			if (style.display === 'none' || style.visibility === 'hidden') continue;
			const rect = el.getBoundingClientRect();
			if (rect.width === 0 || rect.height === 0) continue;
			const text = (el.innerText || '').trim();
			if (!text || text.length > 80) continue;
			if (el.tagName === 'A') {
				const href = el.getAttribute('href');
				if (href && href !== '#' && !href.startsWith('javascript:')) continue;
			}

			seen.add(el);
			out.push(el);
		}
	}
	return out;
}`

// discoverClickNav looks for pages reachable only via a JS click handler (no real href to read
// statically) by clicking heuristically-identified candidates on the current page and observing
// whether the URL changes. It's deliberately opt-in (CrawlOptions.ClickNav) since, unlike
// href-based crawling, it interacts with arbitrary UI elements rather than just reading
// attributes — the destructive-keyword check is applied to each candidate's visible text before
// it gets clicked, same as for regular links, but a text-only check can't catch an icon-only
// destructive control (which this heuristic already tends to exclude anyway, since icon-only
// controls usually have no visible innerText to match the "non-trivial text" requirement above).
//
// Candidate elements are re-queried after every click rather than reused, because a click that
// causes navigation invalidates every other element handle from the pre-click DOM (the old
// document is gone) — there's no way to know in advance which candidates a given click will
// invalidate, so the safe approach is to never assume a stale handle is still good.
//
// tried is shared across the whole crawl (owned by the caller), not created fresh per page: a
// persistent nav/sidebar repeats the same candidates on every page it appears on, and without a
// crawl-wide set the same items would get re-clicked from scratch on every single page visited.
func discoverClickNav(page *rod.Page, originalURL, base *url.URL, opts CrawlOptions, depth int, queryVariantCounts map[string]int, tried map[string]bool, excludeRules []ExcludeRule, result *CrawlResult) []queueItem {
	var discovered []queueItem

	maxCandidates := opts.MaxClickCandidates
	if maxCandidates == 0 {
		maxCandidates = 30
	}

	for attempts := 0; attempts < maxCandidates; attempts++ {
		logf("click-nav: querying candidates (attempt %d/%d) on %s", attempts+1, maxCandidates, originalURL.String())
		candidates, err := page.ElementsByJS(rod.Eval(clickCandidatesJS))
		if err != nil {
			result.Errors = append(result.Errors, "click-nav candidate search on "+originalURL.String()+" failed: "+err.Error())
			return discovered
		}
		logf("click-nav: found %d candidate(s)", len(candidates))

		target, text := nextUntried(candidates, tried)
		if target == nil {
			logf("click-nav: nothing untried left on %s", originalURL.String())
			break // nothing new left to try on this page
		}
		tried[text] = true

		if isDestructiveLink("", text) {
			logf("click-nav: skipping %q (destructive keyword match)", text)
			continue
		}

		logf("click-nav: clicking %q", text)
		// A JS-dispatched click (this.click()) rather than rod's real mouse-coordinate-simulated
		// Element.Click() -- simpler, and avoids any dependency on the element's exact on-screen
		// position/visibility.
		if _, err := target.Eval(`() => this.click()`); err != nil {
			logf("click-nav: click on %q failed: %v", text, err)
			continue // element may have gone stale between the query and the click; skip it
		}

		// Poll for a URL change instead of a single fixed sleep-then-check: confirmed against
		// the real target that some nav entries take over a second to actually navigate (likely
		// fetching data before committing the route change) while most navigate near-instantly.
		// A short fixed wait was mistakenly concluding "did not navigate" on exactly the slower
		// entries, silently missing real destinations. Polling lets fast entries proceed quickly
		// while still giving slow ones enough time.
		afterURL, err := pollForURLChange(page, originalURL, clickNavWaitTimeout, clickNavPollInterval)
		if err != nil {
			logf("click-nav: reading page info after clicking %q failed: %v", text, err)
			continue
		}

		if normalize(afterURL) == normalize(originalURL) {
			logf("click-nav: %q did not navigate (still on %s)", text, afterURL.String())
			// The click may still have triggered an in-place refresh (a dashboard re-fetching
			// its own data, a menu item that's also a "reload this view" action) that briefly
			// clears the DOM before re-rendering. Without settling here, the very next candidate
			// query can catch that transient empty state and wrongly conclude nothing is left to
			// try, silently truncating discovery on this page.
			settleAfterLoad(page)
			continue
		}

		logf("click-nav: %q navigated to %s", text, afterURL.String())

		if isExcluded(afterURL, excludeRules) {
			// Don't attempt to navigate back from a page the user explicitly excluded (e.g. a
			// device setup wizard) -- if it blocks or warns on leaving, that's exactly the kind
			// of page we have no business trying to force our way out of. Abandon the rest of
			// this page's candidates here; the main crawl loop's next normal navigation (which
			// already has its own dialog-handling and timeout) will move us on regardless.
			logf("click-nav: %s is excluded, abandoning further candidates on this page", afterURL.String())
			return discovered
		}

		if isInScopeForCrawl(base, opts, afterURL, queryVariantCounts, excludeRules) {
			discovered = append(discovered, queueItem{url: afterURL, depth: depth + 1})
		}

		// Navigating away invalidated every remaining candidate handle regardless of whether we
		// enqueued this destination — go back so the next iteration's fresh query sees the
		// original page's candidates again.
		logf("click-nav: returning to %s", originalURL.String())
		if err := navigateWithTimeout(page, originalURL.String()); err != nil {
			result.Errors = append(result.Errors, "click-nav: returning to "+originalURL.String()+" failed: "+err.Error())
			return discovered
		}
		logf("click-nav: back on %s, settling", originalURL.String())
		settleAfterLoad(page)
		logf("click-nav: settled, continuing candidate search")
	}

	return discovered
}

const (
	clickNavPollInterval = 250 * time.Millisecond
	// clickNavWaitTimeout is generous on purpose: these are IoT/embedded devices that prioritize
	// camera recording/viewing over web responsiveness, so a route change can take noticeably
	// longer than on typical web infrastructure -- confirmed against a real device that some nav
	// entries take over a second already; 10s gives real headroom under heavier device load.
	clickNavWaitTimeout = 10 * time.Second
)

// pollForURLChange polls the page's current URL every interval, returning as soon as it differs
// from originalURL, or the current URL once timeout elapses with no change (a non-navigating
// click, or a still-in-flight one slower than we're willing to wait for).
func pollForURLChange(page *rod.Page, originalURL *url.URL, timeout, interval time.Duration) (*url.URL, error) {
	deadline := time.Now().Add(timeout)
	for {
		info, err := page.Info()
		if err != nil {
			return nil, err
		}
		current, err := url.Parse(info.URL)
		if err != nil {
			return nil, err
		}
		if normalize(current) != normalize(originalURL) {
			return current, nil
		}
		if time.Now().After(deadline) {
			return current, nil
		}
		time.Sleep(interval)
	}
}

// nextUntried returns the first candidate whose trimmed visible text hasn't been tried yet.
func nextUntried(candidates rod.Elements, tried map[string]bool) (*rod.Element, string) {
	for _, el := range candidates {
		text, err := el.Text()
		if err != nil {
			continue
		}
		text = strings.TrimSpace(text)
		if text == "" || tried[text] {
			continue
		}
		return el, text
	}
	return nil, ""
}

// isInScopeForCrawl applies the scheme/scope/exclude/query-variant-cap rules shared by every
// source of discovered URLs (regular links and click-nav destinations alike). The
// destructive-keyword check is deliberately not here — callers apply it themselves against
// whatever link text they have available (an anchor's visible text, or a clicked candidate's),
// since that's a per-source concern, not a scope concern.
func isInScopeForCrawl(base *url.URL, opts CrawlOptions, candidate *url.URL, queryVariantCounts map[string]int, excludeRules []ExcludeRule) bool {
	if candidate.Scheme != "" && candidate.Scheme != "http" && candidate.Scheme != "https" {
		return false
	}
	if !inScope(base, opts.ScopePrefix, candidate) {
		return false
	}
	if isExcluded(candidate, excludeRules) {
		return false
	}
	if candidate.RawQuery != "" {
		if queryVariantCounts[candidate.Path] >= opts.MaxQueryVariantsPerPath {
			return false
		}
		queryVariantCounts[candidate.Path]++
	}
	return true
}
