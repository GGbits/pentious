package crawler

import "time"

// CrawlOptions configures a crawl run. Credentials are deliberately kept out of this struct —
// see Credentials below — so nothing that ends up embedded in a CrawlResult (and therefore
// rendered into the report) can ever carry a plaintext password.
type CrawlOptions struct {
	Host        string
	StartPath   string
	ScopePrefix string // restricts crawling to this path prefix; defaults to dir(StartPath) if empty

	MaxDepth                int           // default 5
	MaxPages                int           // default 200
	MaxQueryVariantsPerPath int           // default 3
	Politeness              time.Duration // default 500ms

	// Exclude is a list of raw --exclude flag values (e.g. "/vmsportal/setup" or
	// "/vmsportal/login?logout"), parsed into ExcludeRules once at the start of Crawl. Anything
	// matching an exclude rule is never enqueued for crawling, regardless of how it was
	// discovered (a regular href or a click-nav destination).
	Exclude []string

	FuzzForms bool // always false in v1; reserved for a future --fuzz-forms mode

	// ClickNav opts into click-based navigation discovery, for apps where menu/nav items have
	// no real href and only navigate via a JS click handler (common in React/Vue/Angular apps).
	// Off by default: unlike href-based crawling, this interacts with arbitrary UI elements, so
	// it's a deliberate, riskier opt-in rather than the default behavior.
	ClickNav           bool
	MaxClickCandidates int // per-page cap on how many click candidates to try; default 30

	LoginPath     string // path of the login page; defaults to StartPath (only used when Credentials != nil)
	PostLoginPath string // path to start crawling from after login; defaults to ScopePrefix
}

// Credentials carries login material for an authenticated crawl. Kept as its own small type,
// separate from CrawlOptions, so a password can never accidentally end up on CrawlResult.
type Credentials struct {
	Username string
	Password string

	UsernameSelector    string // CSS selector override; auto-detected if empty
	PasswordSelector    string // CSS selector override; auto-detected if empty (input[type=password])
	LoginSubmitSelector string // CSS selector override; falls back to form.requestSubmit() if empty
}

type FieldInfo struct {
	Name string
	Type string
}

type FormInfo struct {
	PageURL string
	Action  string
	Method  string
	Fields  []FieldInfo
}

type QueryParamInfo struct {
	PageURL string
	Path    string
	Param   string
}

type Finding struct {
	Kind       string // "reflected-xss" in v1; room for "stored-xss" once form-fuzzing lands
	URL        string
	Param      string
	Payload    string
	Executed   bool
	Vulnerable bool
}

type PageVisit struct {
	URL   string
	Depth int
	Title string
}

// CrawlResult is the full output of a crawl. It never carries a password — only Username, for
// the report's audit trail ("scanned authenticated as X").
type CrawlResult struct {
	Host        string
	StartPath   string
	ScopePrefix string
	MaxDepth    int
	MaxPages    int

	Authenticated bool
	Username      string

	StartedAt  time.Time
	FinishedAt time.Time

	PagesVisited []PageVisit
	Forms        []FormInfo
	QueryParams  []QueryParamInfo
	Findings     []Finding
	Errors       []string // non-fatal per-page errors; a crawl never aborts on one dead link
}
