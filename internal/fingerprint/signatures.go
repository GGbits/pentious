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

// signatures is every known server signature, checked against a malformed-request probe
// response. Add new server software here as new Signature entries -- IdentifyServer scores each
// one independently, so signatures don't need to be mutually exclusive.
var signatures = []Signature{
	{
		Name: "Jetty",
		Checks: []SignatureCheck{
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
		},
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
