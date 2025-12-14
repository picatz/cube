// Command rulegen generates Chrome `declarativeNetRequest` rules from
// Adblock Plus-style filter lists (for example, EasyList/EasyPrivacy).
//
// The goal of rulegen is not to perfectly reproduce every ABP feature (those
// lists are extremely expressive), but to produce a large, high-signal ruleset
// that is:
//   - compatible with Manifest V3 `declarativeNetRequest` static rulesets
//   - deterministic (stable output for the same inputs)
//   - conservative (skips rules with semantics we can’t faithfully express)
//   - less breakage-prone (honors many exception rules + a small allowlist)
//
// Usage (from the repo root):
//
//	go run ./tools/rulegen -out rules.json
//
// By default, rulegen pulls EasyList + EasyPrivacy. Use `-source` to add/replace
// sources, e.g.:
//
//	go run ./tools/rulegen -source easylist=https://…/easylist.txt -source https://…/easyprivacy.txt
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	defaultMaxRules = 30_000
	defaultTimeout  = 45 * time.Second
)

var defaultSources = []source{
	// Core baseline
	{
		Name: "easylist",
		URL:  "https://easylist-downloads.adblockplus.org/easylist.txt",
	},
	{
		Name: "easyprivacy",
		URL:  "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
	},
	// Fanboy’s Annoyance is widely used and maintained; it also subsumes some smaller lists.
	{
		Name: "fanboy_annoyance",
		URL:  "https://easylist-downloads.adblockplus.org/fanboy-annoyance.txt",
	},
}

// A small, pragmatic allowlist for services that are commonly required for
// core site functionality (support chat, ticketing widgets, etc.).
//
// This is intentionally short; exceptions in the upstream lists should do most
// of the heavy lifting. These entries exist as a safety net.
var defaultAllowDomains = []string{
	"intercom.io",
	"intercomcdn.com",
	"zendesk.com",
	"zdassets.com",
	"freshdesk.com",
	"freshchat.com",
	"helpscout.net",
	"crisp.chat",
	"tawk.to",
	"livechatinc.com",
	"gorgias.chat",
	"drift.com",
	"chatlio.com",
	"smartsupp.com",
}

// A small denylist applied to *exception* rules to avoid accidentally allowing
// well-known ad/analytics trackers when a user enables the optional exceptions
// ruleset.
//
// This denylist does not affect block rules.
var defaultExceptionDenyDomains = []string{
	"doubleclick.net",
	"google-analytics.com",
	"googletagmanager.com",
	"googlesyndication.com",
	"googleadservices.com",
	"facebook.com",
	"connect.facebook.net",
}

type options struct {
	OutBlocksPath     string
	OutExceptionsPath string
	OutAllowlistPath  string

	MaxRules     int
	BlocksShards int
	Sources      []source

	// Exceptions controls how ABP exception rules (@@...) are emitted:
	//   - "none":   emit no exception allow rules
	//   - "scoped": emit only exceptions scoped to initiator domains (domain=...)
	//   - "all":    emit all translatable exception rules (still subject to denylist)
	Exceptions string

	AllowDomains            []string
	IncludeBuiltinAllowlist bool

	ExceptionDenyDomains      []string
	ClearExceptionDenyDomains bool

	Timeout            time.Duration
	IncludeMainFrame   bool
	PrintStatsToStderr bool
}

type source struct {
	Name string
	URL  string
}

type sourcesFlag []source

func (f *sourcesFlag) String() string {
	if f == nil || len(*f) == 0 {
		return ""
	}
	var parts []string
	for _, s := range *f {
		parts = append(parts, s.Name+"="+s.URL)
	}
	return strings.Join(parts, ", ")
}

func (f *sourcesFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("empty source")
	}

	name := ""
	raw := v
	if before, after, ok := strings.Cut(v, "="); ok {
		name = strings.TrimSpace(before)
		raw = strings.TrimSpace(after)
	}
	if raw == "" {
		return fmt.Errorf("invalid source %q: missing URL/path", v)
	}
	if name == "" {
		name = inferSourceName(raw)
	}
	*f = append(*f, source{Name: name, URL: raw})
	return nil
}

func inferSourceName(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		base := filepath.Base(u.Path)
		base = strings.TrimSuffix(base, filepath.Ext(base))
		if base != "" && base != "." && base != "/" {
			return base
		}
		return strings.ReplaceAll(u.Host, ".", "_")
	}
	base := filepath.Base(raw)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" || base == "." || base == "/" {
		return "source"
	}
	return base
}

type domainsFlag []string

func (f *domainsFlag) String() string {
	if f == nil || len(*f) == 0 {
		return ""
	}
	return strings.Join(*f, ", ")
}

func (f *domainsFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("empty domain")
	}
	*f = append(*f, v)
	return nil
}

func main() {
	var srcs sourcesFlag
	var allow domainsFlag
	var excDeny domainsFlag

	var opts options
	flag.StringVar(&opts.OutBlocksPath, "out", "rules.json", "output path for generated block rules (static ruleset)")
	flag.StringVar(&opts.OutExceptionsPath, "out-exceptions", "rules.exceptions.json", "output path for generated exception allow rules (static ruleset; disabled by default)")
	flag.StringVar(&opts.OutAllowlistPath, "out-allowlist", "rules.allowlist.json", "output path for generated allowlist allow rules (static ruleset; disabled by default)")
	flag.IntVar(&opts.MaxRules, "max-rules", defaultMaxRules, "maximum number of rules to emit per ruleset (Chrome enforces upper bounds)")
	flag.IntVar(&opts.BlocksShards, "blocks-shards", 4, "number of block ruleset shards to write (rules.json, rules.2.json, ...)")
	flag.Var(&srcs, "source", "filter list source (repeatable). Format: name=url or url or local file path")
	flag.StringVar(&opts.Exceptions, "exceptions", "scoped", "exception rule emission mode: none, scoped, or all")
	flag.Var(&allow, "allow-domain", "allowlist domain (repeatable); merged with a small default allowlist")
	flag.BoolVar(&opts.IncludeBuiltinAllowlist, "builtin-allowlist", true, "include a small built-in allowlist (written to allowlist ruleset; still disabled by default)")
	flag.Var(&excDeny, "exceptions-deny-domain", "domain to deny in exception rules (repeatable); merged with a small built-in denylist")
	flag.BoolVar(&opts.ClearExceptionDenyDomains, "clear-exceptions-denylist", false, "do not include the built-in exception denylist")
	flag.DurationVar(&opts.Timeout, "timeout", defaultTimeout, "per-source fetch timeout")
	flag.BoolVar(&opts.IncludeMainFrame, "include-main-frame", false, "allow rules to match main_frame requests (default excludes)")
	flag.BoolVar(&opts.PrintStatsToStderr, "stats", true, "print generation stats to stderr")
	flag.Parse()

	opts.Sources = slices.Clone(srcs)
	opts.AllowDomains = slices.Clone(allow)
	opts.ExceptionDenyDomains = slices.Clone(excDeny)

	ctx := context.Background()
	if err := run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, "rulegen:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, opts options) error {
	if opts.MaxRules <= 0 {
		return fmt.Errorf("max-rules must be > 0, got %d", opts.MaxRules)
	}
	if opts.OutBlocksPath == "" {
		return errors.New("out path is required")
	}
	if opts.BlocksShards <= 0 {
		return fmt.Errorf("blocks-shards must be > 0, got %d", opts.BlocksShards)
	}

	sources := opts.Sources
	if len(sources) == 0 {
		sources = defaultSources
	}

	allowDomains := []string(nil)
	if opts.IncludeBuiltinAllowlist {
		allowDomains = append(allowDomains, defaultAllowDomains...)
	}
	allowDomains = append(allowDomains, opts.AllowDomains...)
	allowDomains = normalizeDomains(allowDomains)
	allowSet := make(map[string]struct{}, len(allowDomains))
	for _, d := range allowDomains {
		allowSet[d] = struct{}{}
	}

	exceptionDenyDomains := []string(nil)
	if !opts.ClearExceptionDenyDomains {
		exceptionDenyDomains = append(exceptionDenyDomains, defaultExceptionDenyDomains...)
	}
	exceptionDenyDomains = append(exceptionDenyDomains, opts.ExceptionDenyDomains...)
	exceptionDenyDomains = normalizeDomains(exceptionDenyDomains)
	exceptionDenySet := make(map[string]struct{}, len(exceptionDenyDomains))
	for _, d := range exceptionDenyDomains {
		exceptionDenySet[d] = struct{}{}
	}

	client := &http.Client{}

	var parsedAll []abpRule
	statsBySource := make(map[string]parseStats)

	for _, src := range sources {
		src := src
		ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
		body, err := fetchSource(ctx, client, src.URL)
		cancel()
		if err != nil {
			return fmt.Errorf("fetch %s (%s): %w", src.Name, src.URL, err)
		}

		rules, stats, err := parseABPList(bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("parse %s: %w", src.Name, err)
		}
		statsBySource[src.Name] = stats
		parsedAll = append(parsedAll, rules...)
	}

	blocks, exceptions, convertStats, err := convertABPRules(parsedAll, allowSet, exceptionDenySet, opts.Exceptions, !opts.IncludeMainFrame)
	if err != nil {
		return err
	}

	var allowlistCandidates []ruleCandidate
	for _, d := range allowDomains {
		allowlistCandidates = append(allowlistCandidates, ruleCandidate{
			ActionType: "allow",
			Priority:   3,
			Condition: condition{
				RequestDomains: []string{d},
			},
			Source: "allowlist",
		})
	}

	blockCandidates, err := finalizeCandidates(blocks)
	if err != nil {
		return err
	}
	exceptionRules, err := finalizeRules(exceptions, opts.MaxRules)
	if err != nil {
		return err
	}
	allowlistRules, err := finalizeRules(allowlistCandidates, opts.MaxRules)
	if err != nil {
		return err
	}

	blockShardPaths, err := shardPaths(opts.OutBlocksPath, opts.BlocksShards)
	if err != nil {
		return err
	}
	blockShards := splitCandidates(blockCandidates, opts.MaxRules, opts.BlocksShards)
	for i, p := range blockShardPaths {
		if err := writeRulesJSONAtomic(p, rulesFromCandidates(blockShards[i])); err != nil {
			return err
		}
	}
	if opts.OutExceptionsPath != "" {
		if err := writeRulesJSONAtomic(opts.OutExceptionsPath, exceptionRules); err != nil {
			return err
		}
	}
	if opts.OutAllowlistPath != "" {
		if err := writeRulesJSONAtomic(opts.OutAllowlistPath, allowlistRules); err != nil {
			return err
		}
	}

	if opts.PrintStatsToStderr {
		printStats(os.Stderr, sources, statsBySource, convertStats, len(blockCandidates), len(exceptionRules), len(allowlistRules), len(blockShardPaths))
	}

	return nil
}

func excludedResourceTypes(excludeMainFrame bool) []string {
	if !excludeMainFrame {
		return nil
	}
	return []string{"main_frame"}
}

func fetchSource(ctx context.Context, client *http.Client, raw string) ([]byte, error) {
	// Local file paths are useful for reproducibility and testing.
	if looksLikeFilePath(raw) {
		return os.ReadFile(raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "file":
		return os.ReadFile(filepath.FromSlash(u.Path))
	case "http", "https":
		// continue
	default:
		// If it doesn’t look like a URL, try reading it as a path.
		if u.Scheme == "" {
			return os.ReadFile(raw)
		}
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cube-rulegen/1.0")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected HTTP status %s", res.Status)
	}
	return io.ReadAll(res.Body)
}

func looksLikeFilePath(s string) bool {
	// Heuristic: treat obvious relative/absolute paths as files.
	return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "/")
}

type parseStats struct {
	LinesTotal       int
	LinesIgnored     int
	RulesParsed      int
	RulesUnsupported int
}

// abpRule is a parsed subset of ABP network-filtering rules.
// We only keep rules we can conservatively translate to DNR.
type abpRule struct {
	Exception bool
	Host      string
	Path      string
	Options   abpOptions
}

type abpOptions struct {
	DomainType               string   // "firstParty" or "thirdParty"
	ResourceTypes            []string // DNR resourceTypes
	ExcludedResourceTypes    []string
	InitiatorDomains         []string
	ExcludedInitiatorDomains []string
}

func parseABPList(r io.Reader) ([]abpRule, parseStats, error) {
	sc := bufio.NewScanner(r)
	// Filter lists can include long lines; bump the buffer.
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	var rules []abpRule
	var stats parseStats

	for line := range scannerLines(sc) {
		stats.LinesTotal++
		line = strings.TrimSpace(line)
		if line == "" ||
			strings.HasPrefix(line, "!") || // comment
			strings.HasPrefix(line, "[") { // metadata section
			stats.LinesIgnored++
			continue
		}
		// Cosmetic filtering is not expressible in DNR.
		if strings.Contains(line, "##") || strings.Contains(line, "#@#") {
			stats.LinesIgnored++
			continue
		}

		rule, ok, unsupported := parseABPLine(line)
		if !ok {
			stats.LinesIgnored++
			continue
		}
		if unsupported {
			stats.RulesUnsupported++
			continue
		}
		stats.RulesParsed++
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, stats, err
	}
	return rules, stats, nil
}

// scannerLines exposes a scanner’s tokens as an iterator for testability and
// clearer flow control.
func scannerLines(sc *bufio.Scanner) iter.Seq[string] {
	return func(yield func(string) bool) {
		for sc.Scan() {
			if !yield(sc.Text()) {
				return
			}
		}
	}
}

func parseABPLine(line string) (abpRule, bool, bool) {
	r := abpRule{}

	if strings.HasPrefix(line, "@@") {
		r.Exception = true
		line = strings.TrimSpace(strings.TrimPrefix(line, "@@"))
	}

	pattern := line
	opts := ""
	if before, after, ok := strings.Cut(line, "$"); ok {
		pattern = strings.TrimSpace(before)
		opts = strings.TrimSpace(after)
	}

	unsupported := false
	if opts != "" {
		o, ok := parseABPOptions(opts)
		if !ok {
			return abpRule{}, true, true
		}
		if o == nil {
			// "badfilter" or similar indicates the rule should not apply.
			return abpRule{}, false, false
		}
		r.Options = *o
	}

	host, path, ok := parseABPPattern(pattern)
	if !ok {
		return abpRule{}, true, true
	}
	if host == "" {
		return abpRule{}, true, true
	}

	// Conservative safety: do not attempt to translate patterns with host wildcards
	// or unusual characters.
	if strings.ContainsAny(host, "*^") {
		return abpRule{}, true, true
	}

	host = normalizeDomain(host)
	if host == "" {
		return abpRule{}, true, true
	}

	path = strings.ReplaceAll(path, "^", "*")

	r.Host = host
	r.Path = path
	return r, true, unsupported
}

// parseABPOptions parses a comma-delimited ABP options string into a subset of
// DNR-compatible fields.
//
// Returns (nil, true) when the rule should be skipped (e.g. badfilter).
func parseABPOptions(opts string) (*abpOptions, bool) {
	var o abpOptions
	var unknown []string

	for _, raw := range strings.Split(opts, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if raw == "badfilter" {
			return nil, true
		}
		if raw == "third-party" {
			o.DomainType = "thirdParty"
			continue
		}
		if raw == "~third-party" {
			o.DomainType = "firstParty"
			continue
		}

		if before, after, ok := strings.Cut(raw, "="); ok {
			key := strings.TrimSpace(before)
			val := strings.TrimSpace(after)
			switch key {
			case "domain":
				incl, excl := parseABPDomainList(val)
				o.InitiatorDomains = append(o.InitiatorDomains, incl...)
				o.ExcludedInitiatorDomains = append(o.ExcludedInitiatorDomains, excl...)
			default:
				unknown = append(unknown, raw)
			}
			continue
		}

		isNeg := strings.HasPrefix(raw, "~")
		name := strings.TrimPrefix(raw, "~")
		rt, ok := abpResourceTypeToDNR(name)
		if ok {
			if isNeg {
				o.ExcludedResourceTypes = append(o.ExcludedResourceTypes, rt)
			} else {
				o.ResourceTypes = append(o.ResourceTypes, rt)
			}
			continue
		}

		// Many options exist; be conservative and skip rules we can’t interpret.
		unknown = append(unknown, raw)
	}

	o.ResourceTypes = normalizeEnumList(o.ResourceTypes)
	o.ExcludedResourceTypes = normalizeEnumList(o.ExcludedResourceTypes)
	o.InitiatorDomains = normalizeDomains(o.InitiatorDomains)
	o.ExcludedInitiatorDomains = normalizeDomains(o.ExcludedInitiatorDomains)

	// DNR requires only one of resourceTypes/excludedResourceTypes.
	if len(o.ResourceTypes) != 0 && len(o.ExcludedResourceTypes) != 0 {
		return nil, false
	}

	// Options we don't understand can drastically change semantics (e.g. redirect,
	// removeparam). Skip those rules rather than producing a surprising block.
	if len(unknown) != 0 {
		return nil, false
	}

	return &o, true
}

func parseABPDomainList(v string) (include, exclude []string) {
	// ABP uses `|` to separate domains. Some lists occasionally use commas.
	v = strings.ReplaceAll(v, ",", "|")
	for _, part := range strings.Split(v, "|") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "~") {
			if d := normalizeDomain(strings.TrimPrefix(part, "~")); d != "" {
				exclude = append(exclude, d)
			}
			continue
		}
		if d := normalizeDomain(part); d != "" {
			include = append(include, d)
		}
	}
	return include, exclude
}

func abpResourceTypeToDNR(opt string) (string, bool) {
	switch opt {
	case "script":
		return "script", true
	case "image":
		return "image", true
	case "stylesheet":
		return "stylesheet", true
	case "font":
		return "font", true
	case "media":
		return "media", true
	case "object":
		return "object", true
	case "xmlhttprequest":
		return "xmlhttprequest", true
	case "ping":
		return "ping", true
	case "websocket":
		return "websocket", true
	case "subdocument":
		return "sub_frame", true
	default:
		return "", false
	}
}

func parseABPPattern(pattern string) (host, path string, ok bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", "", false
	}

	// We only translate a subset of ABP patterns:
	// - "||host^" or "||host/path"
	// - "|https://host/path" (no wildcards)
	if strings.HasPrefix(pattern, "||") {
		s := strings.TrimPrefix(pattern, "||")
		if s == "" {
			return "", "", false
		}
		i := strings.IndexAny(s, "^/?")
		if i == -1 {
			return s, "", true
		}
		host = s[:i]
		delim := s[i]
		rest := s[i:]
		switch delim {
		case '^':
			// `^` is a separator wildcard. If the rule continues with a path/query,
			// preserve that to keep the rule high-signal.
			if len(rest) >= 2 && (rest[1] == '/' || rest[1] == '?') {
				return host, rest[1:], true
			}
			return host, "", true
		case '/', '?':
			return host, rest, true
		default:
			return "", "", false
		}
	}

	trimmed := strings.TrimLeft(pattern, "|")
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		if strings.ContainsAny(trimmed, "*^") {
			return "", "", false
		}
		u, err := url.Parse(trimmed)
		if err != nil {
			return "", "", false
		}
		if u.Host == "" {
			return "", "", false
		}
		host = u.Host
		path = u.Path
		if path == "" {
			path = "/"
		}
		if u.RawQuery != "" {
			path = path + "?" + u.RawQuery
		}
		return host, path, true
	}

	return "", "", false
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return ""
	}
	if ip := net.ParseIP(d); ip != nil {
		return ""
	}
	// Keep this intentionally simple; filter lists are already curated and
	// punycode domains should be ASCII. We only reject obvious bad input.
	if strings.ContainsAny(d, " \t/") {
		return ""
	}
	return d
}

func normalizeDomains(ds []string) []string {
	seen := make(map[string]struct{}, len(ds))
	var out []string
	for _, d := range ds {
		d = normalizeDomain(d)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

func normalizeEnumList(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := slices.Clone(xs)
	slices.Sort(out)
	out = slices.Compact(out)
	return out
}

type convertStats struct {
	ParsedTotal int

	ConvertedBlocks     int
	ConvertedExceptions int

	SkippedAllowlisted int
	SkippedTooLong     int

	SkippedExceptionsMode       int
	SkippedExceptionsUnscoped   int
	SkippedExceptionsDenylisted int
}

type ruleCandidate struct {
	ActionType string
	Priority   int
	Condition  condition
	Source     string
}

// Rule matches the `declarativeNetRequest` static ruleset schema.
type rule struct {
	ID        int       `json:"id"`
	Priority  int       `json:"priority"`
	Action    action    `json:"action"`
	Condition condition `json:"condition"`
}

type action struct {
	Type string `json:"type"`
}

type condition struct {
	URLFilter                string   `json:"urlFilter,omitempty"`
	RequestDomains           []string `json:"requestDomains,omitempty"`
	ExcludedRequestDomains   []string `json:"excludedRequestDomains,omitempty"`
	DomainType               string   `json:"domainType,omitempty"`
	ResourceTypes            []string `json:"resourceTypes,omitempty"`
	ExcludedResourceTypes    []string `json:"excludedResourceTypes,omitempty"`
	InitiatorDomains         []string `json:"initiatorDomains,omitempty"`
	ExcludedInitiatorDomains []string `json:"excludedInitiatorDomains,omitempty"`
}

func convertABPRules(abp []abpRule, allowSet, exceptionDenySet map[string]struct{}, exceptionsMode string, excludeMainFrame bool) (blocks []ruleCandidate, exceptions []ruleCandidate, stats convertStats, err error) {
	exceptionsMode = strings.ToLower(strings.TrimSpace(exceptionsMode))
	switch exceptionsMode {
	case "", "scoped":
		exceptionsMode = "scoped"
	case "none", "all":
		// ok
	default:
		return nil, nil, convertStats{}, fmt.Errorf("invalid -exceptions value %q (expected none, scoped, or all)", exceptionsMode)
	}

	stats.ParsedTotal = len(abp)

	for _, r := range abp {
		if r.Exception {
			switch exceptionsMode {
			case "none":
				stats.SkippedExceptionsMode++
				continue
			case "scoped":
				if len(r.Options.InitiatorDomains) == 0 {
					stats.SkippedExceptionsUnscoped++
					continue
				}
			case "all":
				// ok
			}
			if isAllowlistedDomain(r.Host, exceptionDenySet) {
				stats.SkippedExceptionsDenylisted++
				continue
			}
		} else {
			if isAllowlistedDomain(r.Host, allowSet) {
				stats.SkippedAllowlisted++
				continue
			}
		}

		filter := urlFilterForDomain(r.Host, r.Path)
		if len(filter) > 1024 {
			stats.SkippedTooLong++
			continue
		}

		c := condition{
			URLFilter:                filter,
			RequestDomains:           []string{r.Host},
			DomainType:               r.Options.DomainType,
			ResourceTypes:            slices.Clone(r.Options.ResourceTypes),
			ExcludedResourceTypes:    slices.Clone(r.Options.ExcludedResourceTypes),
			InitiatorDomains:         slices.Clone(r.Options.InitiatorDomains),
			ExcludedInitiatorDomains: slices.Clone(r.Options.ExcludedInitiatorDomains),
		}
		c = applyResourceTypePolicy(c, excludeMainFrame)

		if r.Path == "" {
			// For simple host-anchored rules, prefer requestDomains for correctness and
			// smaller rules.
			c.URLFilter = ""
		}
		c = canonicalizeCondition(c)

		actionType := "block"
		priority := 1
		if r.Exception {
			actionType = "allow"
			priority = 2
		}

		cand := ruleCandidate{
			ActionType: actionType,
			Priority:   priority,
			Condition:  c,
			Source:     "abp",
		}

		if r.Exception {
			exceptions = append(exceptions, cand)
			stats.ConvertedExceptions++
		} else {
			blocks = append(blocks, cand)
			stats.ConvertedBlocks++
		}
	}

	return blocks, exceptions, stats, nil
}

func canonicalizeCondition(c condition) condition {
	c.RequestDomains = normalizeDomains(c.RequestDomains)
	c.ExcludedRequestDomains = normalizeDomains(c.ExcludedRequestDomains)
	c.ResourceTypes = normalizeEnumList(c.ResourceTypes)
	c.ExcludedResourceTypes = normalizeEnumList(c.ExcludedResourceTypes)
	c.InitiatorDomains = normalizeDomains(c.InitiatorDomains)
	c.ExcludedInitiatorDomains = normalizeDomains(c.ExcludedInitiatorDomains)
	return c
}

func applyResourceTypePolicy(c condition, excludeMainFrame bool) condition {
	// DNR only allows one of resourceTypes/excludedResourceTypes. If we have both,
	// prefer skipping the rule earlier (we treat it as unsupported), but be
	// defensive here too.
	if len(c.ResourceTypes) != 0 && len(c.ExcludedResourceTypes) != 0 {
		// Keep the narrower interpretation.
		c.ExcludedResourceTypes = nil
	}

	if !excludeMainFrame {
		// Best-effort only: when neither field is set, Chrome defaults to excluding
		// main_frame anyway, so "include main_frame" would require enumerating all
		// resource types. We keep current behavior.
		return c
	}

	if len(c.ResourceTypes) != 0 {
		// main_frame is not present in our mapping; keep as-is.
		return c
	}

	if len(c.ExcludedResourceTypes) == 0 {
		// If neither is specified, Chrome defaults to excluding main_frame already.
		return c
	}

	// excludedResourceTypes matches "all resource types except excluded". Ensure
	// main_frame is excluded so we don't accidentally block navigation.
	for _, rt := range c.ExcludedResourceTypes {
		if rt == "main_frame" {
			return c
		}
	}
	c.ExcludedResourceTypes = append(c.ExcludedResourceTypes, "main_frame")
	return c
}

func urlFilterForDomain(domain, path string) string {
	// Use the DNR urlFilter pattern syntax (ABP-like) so that `||example.com`
	// matches both `example.com` and its subdomains.
	//
	// Importantly, using `*://*.example.com/*` does NOT match `https://example.com/...`
	// because it requires a literal '.' before `example.com`.
	base := "||" + domain

	if path == "" {
		return base + "/"
	}

	// Ensure path begins with "/" or "?" for a reasonable URL shape.
	switch {
	case strings.HasPrefix(path, "/"):
		// ok
	case strings.HasPrefix(path, "?"):
		path = "/*" + path
	default:
		path = "/*" + path
	}

	if strings.HasSuffix(path, "*") {
		return base + path
	}
	return base + path + "*"
}

func isAllowlistedDomain(domain string, allowSet map[string]struct{}) bool {
	// Exact match.
	if _, ok := allowSet[domain]; ok {
		return true
	}
	// Suffix match with dot boundary (e.g., allow "intercom.io" matches "widget.intercom.io").
	for allow := range allowSet {
		if domain == allow {
			return true
		}
		if strings.HasSuffix(domain, "."+allow) {
			return true
		}
	}
	return false
}

func finalizeRules(candidates []ruleCandidate, maxRules int) ([]rule, error) {
	sorted, err := finalizeCandidates(candidates)
	if err != nil {
		return nil, err
	}
	if len(sorted) > maxRules {
		sorted = sorted[:maxRules]
	}
	return rulesFromCandidates(sorted), nil
}

func rulesFromCandidates(candidates []ruleCandidate) []rule {
	out := make([]rule, 0, len(candidates))
	for i, c := range candidates {
		out = append(out, rule{
			ID:        i + 1,
			Priority:  c.Priority,
			Action:    action{Type: c.ActionType},
			Condition: c.Condition,
		})
	}
	return out
}

func finalizeCandidates(candidates []ruleCandidate) ([]ruleCandidate, error) {
	// Deduplicate with a stable key.
	seen := make(map[string]ruleCandidate, len(candidates))
	for _, c := range candidates {
		key, err := candidateKey(c)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = c
	}

	deduped := make([]ruleCandidate, 0, len(seen))
	for c := range maps.Values(seen) {
		deduped = append(deduped, c)
	}

	hostFreq := make(map[string]int, len(deduped))
	baseFreq := make(map[string]int, len(deduped))
	for _, c := range deduped {
		host := conditionHost(c.Condition)
		if host == "" {
			continue
		}
		hostFreq[host]++
		base := baseDomain(host)
		if base != "" {
			baseFreq[base]++
		}
	}

	// Deterministic order: allow first (higher priority), then blocks.
	slices.SortFunc(deduped, func(a, b ruleCandidate) int {
		if a.Priority != b.Priority {
			return cmpDesc(a.Priority, b.Priority)
		}
		if a.ActionType != b.ActionType {
			// allow before block for same priority (defensive)
			if a.ActionType == "allow" {
				return -1
			}
			if b.ActionType == "allow" {
				return 1
			}
		}

		ah := conditionHost(a.Condition)
		bh := conditionHost(b.Condition)
		abBase := baseFreq[baseDomain(ah)]
		bbBase := baseFreq[baseDomain(bh)]
		if abBase != bbBase {
			return cmpDesc(abBase, bbBase)
		}
		ahf := hostFreq[ah]
		bhf := hostFreq[bh]
		if ahf != bhf {
			return cmpDesc(ahf, bhf)
		}

		ab := urlFilterBreadthScore(a.Condition.URLFilter)
		bb := urlFilterBreadthScore(b.Condition.URLFilter)
		if ab != bb {
			return cmpDesc(ab, bb)
		}
		ac := conditionSpecificityScore(a.Condition)
		bc := conditionSpecificityScore(b.Condition)
		if ac != bc {
			return cmpAsc(ac, bc)
		}
		if len(a.Condition.URLFilter) != len(b.Condition.URLFilter) {
			return cmpAsc(len(a.Condition.URLFilter), len(b.Condition.URLFilter))
		}
		if a.Condition.URLFilter != b.Condition.URLFilter {
			return strings.Compare(a.Condition.URLFilter, b.Condition.URLFilter)
		}
		aj, _ := json.Marshal(a.Condition)
		bj, _ := json.Marshal(b.Condition)
		return bytes.Compare(aj, bj)
	})

	return deduped, nil
}

func urlFilterHost(f string) string {
	if !strings.HasPrefix(f, "||") {
		return ""
	}
	s := strings.TrimPrefix(f, "||")
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

func conditionHost(c condition) string {
	if h := urlFilterHost(c.URLFilter); h != "" {
		return h
	}
	if len(c.RequestDomains) == 1 {
		return c.RequestDomains[0]
	}
	return ""
}

func baseDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, ".")
	host = strings.TrimSuffix(host, ".")
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func cmpDesc(a, b int) int {
	if a == b {
		return 0
	}
	if a > b {
		return -1
	}
	return 1
}

func cmpAsc(a, b int) int {
	if a == b {
		return 0
	}
	if a < b {
		return -1
	}
	return 1
}

// urlFilterBreadthScore ranks patterns by how broadly they match:
// higher is broader.
func urlFilterBreadthScore(f string) int {
	// Prefer domain-only rules `||example.com/` to path-specific rules.
	if strings.HasPrefix(f, "||") && strings.HasSuffix(f, "/") && !strings.Contains(f, "*") {
		return 3
	}
	// Next: domain anchored with some path.
	if strings.HasPrefix(f, "||") {
		return 2
	}
	return 1
}

// conditionSpecificityScore ranks conditions by how narrowly they match:
// lower is broader.
func conditionSpecificityScore(c condition) int {
	score := 0
	if c.DomainType != "" {
		score++
	}
	if len(c.ResourceTypes) != 0 {
		score++
	}
	if len(c.ExcludedResourceTypes) != 0 {
		score++
	}
	if len(c.InitiatorDomains) != 0 {
		score += 2
	}
	if len(c.ExcludedInitiatorDomains) != 0 {
		score++
	}
	return score
}

func candidateKey(c ruleCandidate) (string, error) {
	cond := canonicalizeCondition(c.Condition)
	b, err := json.Marshal(cond)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s|%d|%s", c.ActionType, c.Priority, string(b)), nil
}

func writeRulesJSONAtomic(path string, rules []rule) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".rules.json.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rules); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func printStats(w io.Writer, sources []source, parseBySource map[string]parseStats, conv convertStats, totalBlocks, totalExceptions, totalAllowlist, blockShards int) {
	fmt.Fprintf(w, "rulegen: generated blocks=%d (shards=%d) exceptions=%d allowlist=%d\n", totalBlocks, blockShards, totalExceptions, totalAllowlist)
	for _, src := range sources {
		if st, ok := parseBySource[src.Name]; ok {
			fmt.Fprintf(w, "  %s: lines=%d parsed=%d unsupported=%d ignored=%d\n",
				src.Name, st.LinesTotal, st.RulesParsed, st.RulesUnsupported, st.LinesIgnored)
		}
	}
	fmt.Fprintf(w, "  converted: blocks=%d exceptions=%d skipped_allowlisted=%d skipped_toolong=%d\n",
		conv.ConvertedBlocks, conv.ConvertedExceptions, conv.SkippedAllowlisted, conv.SkippedTooLong)
	fmt.Fprintf(w, "  exceptions: skipped_mode=%d skipped_unscoped=%d skipped_denylisted=%d\n",
		conv.SkippedExceptionsMode, conv.SkippedExceptionsUnscoped, conv.SkippedExceptionsDenylisted)
}

func shardPaths(out string, shards int) ([]string, error) {
	if shards <= 0 {
		return nil, fmt.Errorf("shards must be > 0, got %d", shards)
	}
	if shards == 1 {
		return []string{out}, nil
	}
	ext := filepath.Ext(out)
	if ext == "" {
		return nil, fmt.Errorf("out path %q must have an extension (e.g. .json) to shard", out)
	}
	base := strings.TrimSuffix(out, ext)
	paths := make([]string, 0, shards)
	paths = append(paths, out)
	for i := 2; i <= shards; i++ {
		paths = append(paths, fmt.Sprintf("%s.%d%s", base, i, ext))
	}
	return paths, nil
}

func splitCandidates(candidates []ruleCandidate, maxPerShard, shards int) [][]ruleCandidate {
	out := make([][]ruleCandidate, shards)
	for i := 0; i < shards; i++ {
		start := i * maxPerShard
		if start >= len(candidates) {
			out[i] = nil
			continue
		}
		end := start + maxPerShard
		if end > len(candidates) {
			end = len(candidates)
		}
		out[i] = candidates[start:end]
	}
	return out
}
