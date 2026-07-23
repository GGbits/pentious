package crawler

import (
	"fmt"
	"sort"
	"strings"
)

// RenderMarkdown produces the full human-readable report for a completed crawl: target info,
// scan mode, findings (vulnerable first, so the actionable part is at the top for a client-facing
// deliverable), then the attack-surface inventory, then any non-fatal errors encountered.
func RenderMarkdown(result *CrawlResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# pentious Scan Report\n\n")
	fmt.Fprintf(&b, "**Target:** https://%s%s\n\n", result.Host, result.StartPath)
	fmt.Fprintf(&b, "**Scope prefix:** %s\n\n", result.ScopePrefix)
	if result.Authenticated {
		fmt.Fprintf(&b, "**Mode:** Authenticated (user: %s)\n\n", result.Username)
	} else {
		fmt.Fprintf(&b, "**Mode:** Unauthenticated\n\n")
	}
	fmt.Fprintf(&b, "**Started:** %s   **Finished:** %s\n\n", result.StartedAt.Format(rfc3339), result.FinishedAt.Format(rfc3339))
	fmt.Fprintf(&b, "**Pages visited:** %d / %d max   **Max depth:** %d\n\n", len(result.PagesVisited), result.MaxPages, result.MaxDepth)

	renderFindings(&b, result.Findings)
	renderInventory(&b, result)
	renderErrors(&b, result.Errors)

	return b.String()
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"

func renderFindings(b *strings.Builder, findings []Finding) {
	fmt.Fprintf(b, "## Findings\n\n")

	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return findingRank(sorted[i]) < findingRank(sorted[j])
	})

	var vulnerable, notVulnerable []Finding
	for _, f := range sorted {
		if f.Vulnerable {
			vulnerable = append(vulnerable, f)
		} else {
			notVulnerable = append(notVulnerable, f)
		}
	}

	fmt.Fprintf(b, "### VULNERABLE (%d)\n\n", len(vulnerable))
	if len(vulnerable) == 0 {
		fmt.Fprintf(b, "None found.\n\n")
	}
	for _, f := range vulnerable {
		tag := "reflected, unescaped"
		if f.Executed {
			tag = "executed"
		}
		fmt.Fprintf(b, "- **[%s]** `%s` param at %s\n", tag, f.Param, f.URL)
	}
	b.WriteString("\n")

	fmt.Fprintf(b, "### Not vulnerable (%d)\n\n", len(notVulnerable))
	for _, f := range notVulnerable {
		fmt.Fprintf(b, "- `%s` param at %s\n", f.Param, f.URL)
	}
	b.WriteString("\n")
}

// findingRank sorts executed > reflected-unescaped > not-vulnerable.
func findingRank(f Finding) int {
	switch {
	case f.Executed:
		return 0
	case f.Vulnerable:
		return 1
	default:
		return 2
	}
}

func renderInventory(b *strings.Builder, result *CrawlResult) {
	fmt.Fprintf(b, "## Attack Surface Inventory\n\n")

	fmt.Fprintf(b, "### Pages Crawled (%d)\n\n", len(result.PagesVisited))
	for _, p := range result.PagesVisited {
		fmt.Fprintf(b, "- %s (depth %d)\n", p.URL, p.Depth)
	}
	b.WriteString("\n")

	fmt.Fprintf(b, "### Forms Found (%d)\n\n", len(result.Forms))
	for _, f := range result.Forms {
		fmt.Fprintf(b, "#### %s (%s)\n\n", f.Action, f.Method)
		fmt.Fprintf(b, "Found on: %s\n\n", f.PageURL)
		if len(f.Fields) > 0 {
			fmt.Fprintf(b, "| Field | Type |\n|---|---|\n")
			for _, field := range f.Fields {
				fmt.Fprintf(b, "| %s | %s |\n", field.Name, field.Type)
			}
			b.WriteString("\n")
		}
	}

	fmt.Fprintf(b, "### Query Parameters Found (%d)\n\n", len(result.QueryParams))
	if len(result.QueryParams) > 0 {
		fmt.Fprintf(b, "| Path | Param |\n|---|---|\n")
		for _, q := range result.QueryParams {
			fmt.Fprintf(b, "| %s | %s |\n", q.Path, q.Param)
		}
		b.WriteString("\n")
	}
}

func renderErrors(b *strings.Builder, errs []string) {
	if len(errs) == 0 {
		return
	}
	fmt.Fprintf(b, "## Errors During Crawl (%d)\n\n", len(errs))
	for _, e := range errs {
		fmt.Fprintf(b, "- %s\n", e)
	}
}
