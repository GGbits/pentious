package scanner

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type XSSResult struct {
	URL        string
	Payload    string
	Vulnerable bool
	StatusCode int
}

func ReflectedXSS(client *http.Client, host, queryParam, payload string) (*XSSResult, error) {
	target := fmt.Sprintf("https://%s/?%s=%s", host, queryParam, url.QueryEscape(payload))

	resp, err := client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Look for the raw unescaped payload — if the server HTML-encoded it
	// (e.g. &lt;script&gt;) this check fails, meaning the input is sanitised.
	vulnerable := strings.Contains(string(body), payload)

	return &XSSResult{
		URL:        target,
		Payload:    payload,
		Vulnerable: vulnerable,
		StatusCode: resp.StatusCode,
	}, nil
}

type StoredXSSResult struct {
	PostURL    string
	VerifyURL  string
	Payload    string
	CSRFToken  string
	PostStatus int
	Vulnerable bool
	Verified   bool
}

func StoredXSS(client *http.Client, host, path, attackField, payload string, fields map[string]string, verifyPath, csrfFrom, csrfField string) (*StoredXSSResult, error) {
	result := &StoredXSSResult{
		PostURL: fmt.Sprintf("https://%s%s", host, path),
		Payload: payload,
	}

	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}

	if csrfFrom != "" {
		csrfURL := fmt.Sprintf("https://%s%s", host, csrfFrom)
		token, err := fetchCSRFToken(client, csrfURL, csrfField)
		if err != nil {
			return nil, fmt.Errorf("CSRF fetch failed: %w", err)
		}
		result.CSRFToken = token
		form.Set(csrfField, token)
	}

	form.Set(attackField, payload)

	resp, err := client.PostForm(result.PostURL, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain so the connection can be reused

	result.PostStatus = resp.StatusCode

	if verifyPath == "" {
		return result, nil
	}

	verifyURL := fmt.Sprintf("https://%s%s", host, verifyPath)
	result.VerifyURL = verifyURL
	result.Verified = true

	vresp, err := client.Get(verifyURL)
	if err != nil {
		return result, fmt.Errorf("post succeeded but verify GET failed: %w", err)
	}
	defer vresp.Body.Close()

	body, err := io.ReadAll(vresp.Body)
	if err != nil {
		return result, err
	}

	// Same check as reflected: raw unescaped payload present means the stored
	// content is rendered without sanitisation.
	result.Vulnerable = strings.Contains(string(body), payload)

	return result, nil
}

// fetchCSRFToken GETs the given URL and walks the HTML tree to find the value
// of the hidden input whose name matches fieldName.
func fetchCSRFToken(client *http.Client, pageURL, fieldName string) (string, error) {
	resp, err := client.Get(pageURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	var token string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, a := range n.Attr {
				switch a.Key {
				case "name":
					name = a.Val
				case "value":
					value = a.Val
				}
			}
			if name == fieldName {
				token = value
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	if token == "" {
		return "", fmt.Errorf("field %q not found in %s", fieldName, pageURL)
	}
	return token, nil
}
