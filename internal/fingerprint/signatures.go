package fingerprint

import (
	"fmt"
	"sort"
	"strings"
)

// SignatureCheck is a single named test for one server-specific tell in a malformed-request
// probe response. Name is shown to the user alongside a pass/fail mark, so it should read as a
// standalone explanation of what's being checked and why it's meaningful.
type SignatureCheck struct {
	Name    string
	Matches func(*MalformedResult) bool
}

// Signature is a named server software identity backed by one or more SignatureChecks. More
// matched checks (relative to the signature's total) means higher confidence that response came
// from that server software.
type Signature struct {
	Name   string
	Checks []SignatureCheck
}

// CheckResult is one Signature check's outcome against a specific probe response.
type CheckResult struct {
	Name    string
	Matched bool
}

// SignatureMatch is how many of a Signature's checks matched a given probe response.
type SignatureMatch struct {
	Signature string
	Results   []CheckResult
}

// MatchedCount returns how many of the signature's checks matched.
func (m SignatureMatch) MatchedCount() int {
	n := 0
	for _, r := range m.Results {
		if r.Matched {
			n++
		}
	}
	return n
}

// Total returns the total number of checks the signature defines.
func (m SignatureMatch) Total() int {
	return len(m.Results)
}

// jettyBaseChecks match every Jetty version from 9.4 through 12.1 equally -- confirmed by diffing
// org.eclipse.jetty.server.handler.ErrorHandler's source across the jetty-9.4.58, jetty-10.0.26,
// jetty-11.0.26, jetty-12.0.38, and jetty-12.1.12 release tags, where the code producing these
// traits is byte-for-byte identical. They establish "this is Jetty"; each entry in the
// signatures slice below adds one more check to narrow down which era of Jetty it is.
var jettyBaseChecks = []SignatureCheck{
	{
		Name: `error body's URI field is the literal "/badMessage" (Jetty's internal placeholder target for requests that failed to parse far enough to have a real one)`,
		Matches: func(r *MalformedResult) bool {
			return strings.Contains(r.Body, "/badMessage")
		},
	},
	{
		Name: `error body reports "Unknown Version" as the 505 message -- Jetty's own internal wording for a malformed HTTP-version token, kept separate from the standard "HTTP Version Not Supported" reason phrase it puts on the actual status line`,
		Matches: func(r *MalformedResult) bool {
			return r.StatusCode == 505 && strings.Contains(r.Body, "Unknown Version")
		},
	},
	{
		Name: `error body matches Jetty's default ErrorHandler layout ("HTTP ERROR" heading plus a URI/STATUS/MESSAGE table)`,
		Matches: func(r *MalformedResult) bool {
			return strings.Contains(r.Body, "HTTP ERROR") &&
				strings.Contains(r.Body, "<th>URI:</th>") &&
				strings.Contains(r.Body, "<th>STATUS:</th>") &&
				strings.Contains(r.Body, "<th>MESSAGE:</th>")
		},
	},
	{
		Name: `error body declares charset=ISO-8859-1 (Jetty's default ErrorHandler template charset)`,
		Matches: func(r *MalformedResult) bool {
			return strings.Contains(r.Body, "charset=ISO-8859-1")
		},
	},
	{
		// Jetty's http3 module wires up HTTP3ServerConnectionFactory, which registers a
		// customizer that adds "Alt-Svc: h3=..." but ONLY to responses served over HTTP/2 --
		// confirmed identical (down to the HttpVersion.HTTP_2 guard) in jetty-10.0.26,
		// jetty-11.0.26, and jetty-12.0.38's HTTP3ServerConnectionFactory.java. jetty-9.4 never
		// shipped an http3 module at all (no jetty-http3 directory exists in that tag), and
		// jetty-12.1.12's source no longer contains this Alt-Svc auto-advertisement anywhere
		// (grepped the full tree, zero matches) -- it was removed sometime after 12.0.x. So a
		// match here also weighs against both 9.4 and 12.1 specifically. It's opt-in
		// (the http3 module isn't on by default) and Jetty itself calls HTTP/3 support
		// "experimental," so its absence doesn't rule anything out.
		Name: `the normal request's response carries an "Alt-Svc" header advertising h3 -- Jetty's http3 module auto-adds this, but only over HTTP/2, never existed in jetty-9.4, and was removed from jetty-12.1's source, so a match here weighs against both 9.4 and 12.1`,
		Matches: func(r *MalformedResult) bool {
			return strings.Contains(r.NormalAltSvc, "h3")
		},
	},
}

// jettyChecks returns a copy of jettyBaseChecks with one extra, version-family-specific check
// appended, so each family signature can be edited independently without aliasing the shared
// base slice's backing array.
func jettyChecks(extra SignatureCheck) []SignatureCheck {
	checks := make([]SignatureCheck, len(jettyBaseChecks), len(jettyBaseChecks)+1)
	copy(checks, jettyBaseChecks)
	return append(checks, extra)
}

// signatures is every known server signature, checked against a malformed-request probe
// response. Add new server software here as new Signature entries -- IdentifyServer scores each
// one independently, so signatures don't need to be mutually exclusive.
var signatures = []Signature{
	{
		// jetty-9.4.58, jetty-10.0.26, and jetty-11.0.26's ErrorHandler.writeErrorPage write
		// "</head>\n<body>" with no trailing newline, so the body's opening tag and the <h2>
		// heading that immediately follows land on the same line with nothing between them.
		Name: "Jetty 9.x / 10.x / 11.x",
		Checks: jettyChecks(SignatureCheck{
			Name: `<body> is immediately followed by the <h2> heading on the same line, no newline between them -- the exact byte layout ErrorHandler.writeErrorPage emits in the pre-12 codebase (verified against jetty-9.4.58, jetty-10.0.26, jetty-11.0.26)`,
			Matches: func(r *MalformedResult) bool {
				return strings.Contains(r.Body, "<body><h2>HTTP ERROR")
			},
		}),
	},
	{
		// jetty-12.0.38 and jetty-12.1.12's rewritten ErrorHandler.writeErrorHtml instead writes
		// "</head>\n<body>\n", adding a newline before the <h2> heading that 9.x/10.x/11.x don't have.
		Name: "Jetty 12.0 / 12.1",
		Checks: jettyChecks(SignatureCheck{
			Name: `<body> is followed by a newline before the <h2> heading -- the exact byte layout ErrorHandler.writeErrorHtml emits in the jetty-12 rewrite (verified against jetty-12.0.38, jetty-12.1.12)`,
			Matches: func(r *MalformedResult) bool {
				return strings.Contains(r.Body, "<body>\n<h2>HTTP ERROR")
			},
		}),
	},
	{
		Name: "Tomcat",
		Checks: []SignatureCheck{
			{
				Name: `error body's <title> repeats "HTTP Status <code>" -- the fixed heading Tomcat's default ErrorReportValve template uses`,
				Matches: func(r *MalformedResult) bool {
					return strings.Contains(r.Body, fmt.Sprintf("<title>HTTP Status %d", r.StatusCode))
				},
			},
			{
				Name: `error body's <h1> also repeats "HTTP Status <code>" -- ErrorReportValve prints the same status text twice, once in the title and once in the page heading`,
				Matches: func(r *MalformedResult) bool {
					return strings.Contains(r.Body, fmt.Sprintf("<h1>HTTP Status %d", r.StatusCode))
				},
			},
			{
				Name: `error body's inline stylesheet uses Tomcat's default ErrorReportValve palette (background-color:#525D76, Tahoma/Arial font stack)`,
				Matches: func(r *MalformedResult) bool {
					return strings.Contains(r.Body, "background-color:#525D76") &&
						strings.Contains(r.Body, "font-family:Tahoma,Arial,sans-serif")
				},
			},
			{
				Name: `error body embeds Tomcat's ".line" divider CSS rule (".line {height:1px;background-color:#525D76;border:none;}") from the same ErrorReportValve template`,
				Matches: func(r *MalformedResult) bool {
					return strings.Contains(r.Body, ".line {height:1px;background-color:#525D76;border:none;}")
				},
			},
		},
	},
}

// IdentifyServer scores every known Signature against a malformed-request probe response and
// returns one SignatureMatch per signature, sorted by most-matched-checks first.
func IdentifyServer(r *MalformedResult) []SignatureMatch {
	matches := make([]SignatureMatch, 0, len(signatures))
	for _, sig := range signatures {
		m := SignatureMatch{Signature: sig.Name}
		for _, c := range sig.Checks {
			m.Results = append(m.Results, CheckResult{Name: c.Name, Matched: c.Matches(r)})
		}
		matches = append(matches, m)
	}

	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].MatchedCount() > matches[j].MatchedCount()
	})

	return matches
}
