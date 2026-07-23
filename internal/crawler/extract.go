package crawler

import (
	"net/url"
	"sort"
	"strings"

	"github.com/go-rod/rod"
)

// resolve resolves href relative to base. *url.URL has no Parse method of its own — relative
// references must go through the package-level url.Parse + URL.ResolveReference.
func resolve(base *url.URL, href string) (*url.URL, error) {
	ref, err := url.Parse(href)
	if err != nil {
		return nil, err
	}
	resolved := base.ResolveReference(ref)
	resolved.Fragment = "" // don't let #section fragments create fake distinct pages
	return resolved, nil
}

// normalize produces a dedup key for a URL: lowercase scheme+host, default https port stripped,
// no fragment, query keys sorted. Distinct query strings on the same path are kept distinct
// (not collapsed) — see the query-variant cap in crawler.go for why.
func normalize(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	} else if scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}

	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var qs []string
	for _, k := range keys {
		for _, v := range q[k] {
			qs = append(qs, k+"="+v)
		}
	}

	key := scheme + "://" + host + u.Path
	if len(qs) > 0 {
		key += "?" + strings.Join(qs, "&")
	}
	return key
}

// extractQueryParams returns the sorted query parameter names present on pageURL itself.
func extractQueryParams(pageURL *url.URL) []string {
	q := pageURL.Query()
	names := make([]string, 0, len(q))
	for name := range q {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type extractedLink struct {
	URL  *url.URL
	Text string
}

// extractLinks pulls every <a href> from the current page and resolves each href relative to
// pageURL. Scope/denylist filtering happens in the caller (crawler.go) — this stays "what's on
// this page."
func extractLinks(page *rod.Page, pageURL *url.URL) ([]extractedLink, error) {
	anchors, err := page.Elements("a[href]")
	if err != nil {
		return nil, err
	}

	var links []extractedLink
	for _, a := range anchors {
		hrefAttr, err := a.Attribute("href")
		if err != nil || hrefAttr == nil || *hrefAttr == "" {
			continue
		}
		resolved, err := resolve(pageURL, *hrefAttr)
		if err != nil {
			continue
		}
		text, _ := a.Text()
		links = append(links, extractedLink{URL: resolved, Text: text})
	}
	return links, nil
}

// extractForms pulls every <form> on the current page, cataloging its action/method and each
// named field's name+type. It never fills in or submits anything.
func extractForms(page *rod.Page, pageURL *url.URL) ([]FormInfo, error) {
	forms, err := page.Elements("form")
	if err != nil {
		return nil, err
	}

	var out []FormInfo
	for _, f := range forms {
		action := pageURL.String()
		if a, err := f.Attribute("action"); err == nil && a != nil && *a != "" {
			if resolved, err := resolve(pageURL, *a); err == nil {
				action = resolved.String()
			}
		}

		method := "GET"
		if m, err := f.Attribute("method"); err == nil && m != nil && *m != "" {
			method = strings.ToUpper(*m)
		}

		info := FormInfo{PageURL: pageURL.String(), Action: action, Method: method}

		fields, err := f.Elements("input, select, textarea")
		if err != nil {
			return nil, err
		}
		for _, el := range fields {
			name, err := el.Attribute("name")
			if err != nil || name == nil || *name == "" {
				continue // unnamed fields aren't submittable, not useful in the inventory
			}

			typ := "text"
			if tagName, err := el.Property("tagName"); err == nil {
				typ = strings.ToLower(tagName.Str())
			}
			if t, err := el.Attribute("type"); err == nil && t != nil && *t != "" {
				typ = strings.ToLower(*t)
			}

			info.Fields = append(info.Fields, FieldInfo{Name: *name, Type: typ})
		}

		out = append(out, info)
	}
	return out, nil
}
