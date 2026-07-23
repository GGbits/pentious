package crawler

import (
	"net/url"
	"path"
	"strings"
)

// inScope reports whether candidate is same-scheme, same-host as base, and its path falls
// under scopePrefix.
func inScope(base *url.URL, scopePrefix string, candidate *url.URL) bool {
	if !strings.EqualFold(candidate.Scheme, base.Scheme) || !strings.EqualFold(candidate.Host, base.Host) {
		return false
	}
	return strings.HasPrefix(candidate.Path, scopePrefix)
}

// defaultScopePrefix derives the default crawl scope from the start path: its directory,
// e.g. "/vmsportal/login" -> "/vmsportal/". Root paths default to "/".
func defaultScopePrefix(startPath string) string {
	dir := path.Dir(startPath)
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return dir
}

// destructiveKeywords flags links that look like they trigger a destructive/state-changing
// action, or (logout/signout) that would silently downgrade an authenticated crawl to
// anonymous. This is deliberately conservative: matching too much (skipping a page that was
// actually safe) is far cheaper than matching too little (triggering a real action on a
// stateful device). It cannot catch a REST-style destructive action with no telling word in
// its href/text (e.g. a plain "<a href=/api/cams/7>" wired to a delete) — that's a known,
// accepted limitation for v1.
var destructiveKeywords = []string{
	"delete", "remove", "logout", "signout", "log-out", "sign-out",
	"reset", "format", "shutdown", "reboot", "restart", "poweroff",
	"power-off", "destroy", "purge", "erase", "disable", "uninstall",
}

func isDestructiveLink(href, linkText string) bool {
	h := strings.ToLower(href)
	t := strings.ToLower(linkText)
	for _, kw := range destructiveKeywords {
		if strings.Contains(h, kw) || strings.Contains(t, kw) {
			return true
		}
	}
	return false
}

// ExcludeRule is a user-supplied path (optionally with a query parameter) to never crawl to,
// e.g. a device setup wizard or a logout endpoint that the destructive-keyword heuristic doesn't
// catch on its own.
type ExcludeRule struct {
	Path       string // matched as a prefix against the candidate's path
	QueryParam string // if non-empty, the candidate's query string must also contain this key
}

// parseExcludeRules parses --exclude flag values like "/vmsportal/setup" (path only) or
// "/vmsportal/login?logout" (path plus a required query key; the value, if any, is ignored --
// "?logout" and "?logout=1" match the same way).
func parseExcludeRules(raw []string) []ExcludeRule {
	rules := make([]ExcludeRule, 0, len(raw))
	for _, r := range raw {
		p, query, hasQuery := strings.Cut(r, "?")
		rule := ExcludeRule{Path: p}
		if hasQuery {
			if values, err := url.ParseQuery(query); err == nil {
				for k := range values {
					rule.QueryParam = k
					break // one key is all real-world exclude patterns need so far
				}
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

// isExcluded reports whether candidate matches any exclude rule: its path has the rule's path as
// a prefix (so excluding "/vmsportal/setup" also excludes anything under it), and, if the rule
// specifies a query key, candidate's query string must contain that key too.
func isExcluded(candidate *url.URL, rules []ExcludeRule) bool {
	for _, rule := range rules {
		if !strings.HasPrefix(candidate.Path, rule.Path) {
			continue
		}
		if rule.QueryParam != "" && !candidate.Query().Has(rule.QueryParam) {
			continue
		}
		return true
	}
	return false
}
