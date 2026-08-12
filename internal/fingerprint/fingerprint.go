package fingerprint

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const requestTimeout = 10 * time.Second

// maxErrorBodyBytes caps how much of a malformed-request error response body we read back --
// error pages used for this kind of probe are typically small, and capping it keeps a server
// that ignores Content-Length and just streams data from hanging the probe.
const maxErrorBodyBytes = 4096

// malformedRequestTemplate is a request line that violates the HTTP-version grammar (RFC 7230
// 3.1.1 requires exactly "HTTP/DIGIT.DIGIT"). A spec-compliant server must reject it with 400
// Bad Request; how each server phrases and formats that rejection differs enough across server
// software to be a useful signal when the Server header itself is hidden or stripped.
const malformedRequestTemplate = "GET / HTTP/1.1.1\r\nHost: %s\r\n\r\n"

// Result holds the response metadata from a fingerprint request. Headers is the full response
// header set, not just Server -- v1 only surfaces Server, but later fingerprinting phases can
// read Headers directly without a signature change here. Proto is the negotiated protocol (e.g.
// "HTTP/2.0" or "HTTP/1.1") -- some signature checks use whether HTTP/2 was negotiated at all.
type Result struct {
	URL     string
	Headers http.Header
	Proto   string
}

// Fingerprint requests host's root path "/" over HTTPS on the given port and reports its
// response headers. insecure mirrors the root --insecure flag, disabling TLS certificate
// verification the same way the Chrome launcher does for browser-driven commands.
func Fingerprint(host string, port int, insecure bool) (*Result, error) {
	return FingerprintURL(fmt.Sprintf("https://%s/", net.JoinHostPort(host, fmt.Sprint(port))), insecure)
}

// FingerprintURL requests rawURL directly.
func FingerprintURL(rawURL string, insecure bool) (*Result, error) {
	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			// Supplying a custom TLSClientConfig otherwise makes net/http conservatively skip
			// its automatic HTTP/2 upgrade. Some fingerprint checks (e.g. Jetty's Alt-Svc/h3
			// advertisement) only fire on HTTP/2 connections, so force the attempt here.
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	return &Result{URL: rawURL, Headers: resp.Header, Proto: resp.Proto}, nil
}

// MalformedResult holds the response to a deliberately malformed HTTP request, sent as a
// fallback probe when the normal response doesn't carry an identifying Server header.
type MalformedResult struct {
	Host       string
	StatusLine string
	StatusCode int
	Headers    http.Header
	Body       string
	Truncated  bool

	// NormalAltSvc is the Alt-Svc header value from the earlier normal (non-malformed) request,
	// if any. It's not populated by MalformedRequest itself -- the caller sets it from the
	// Result it already has, since re-requesting it here would be redundant. Some signature
	// checks use it alongside the malformed-request body.
	NormalAltSvc string

	// NormalProto is the negotiated protocol (Result.Proto) from that same earlier normal
	// request, set by the caller the same way as NormalAltSvc.
	NormalProto string
}

// MalformedRequest connects to host:port and sends a request line with an invalid HTTP version,
// then reports however the server responds. Different server software formats and words its
// 400 Bad Request response differently, which can help identify it even when the Server header
// itself is absent or stripped. insecure mirrors the root --insecure flag.
func MalformedRequest(host string, port int, insecure bool) (*MalformedResult, error) {
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	dialer := &net.Dialer{Timeout: requestTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: insecure})
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return nil, fmt.Errorf("setting deadline for %s: %w", host, err)
	}

	if _, err := fmt.Fprintf(conn, malformedRequestTemplate, host); err != nil {
		return nil, fmt.Errorf("sending malformed request to %s: %w", host, err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", host, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body from %s: %w", host, err)
	}
	truncated := len(body) > maxErrorBodyBytes
	if truncated {
		body = body[:maxErrorBodyBytes]
	}

	return &MalformedResult{
		Host:       host,
		StatusLine: resp.Status,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(body),
		Truncated:  truncated,
	}, nil
}
