package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
