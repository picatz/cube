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
	// defaultMaxRules is the default maximum number of rules emitted per ruleset shard.
	// (Chrome enforces an upper bound for static rulesets.)
	defaultMaxRules = 30_000

	// defaultTimeout is the default per-source fetch timeout.
	defaultTimeout = 45 * time.Second
)

// defaultSources is the default set of filter list sources used when the user
// does not specify any `-source` flags.
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

// options controls rule generation and output layout.
type options struct {
	OutBlocksPath     string
	OutExceptionsPath string
	OutAllowlistPath  string

	MaxRules     int
	BlocksShards int
	Sources      []source

	// FollowIncludes controls whether to expand `!#include ...` directives
	// (used by some ABP/AdGuard lists) by fetching and parsing the included files.
	FollowIncludes  bool
	MaxIncludeDepth int
	MaxIncludes     int

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

// source describes a single input filter list (remote URL or local file path).
type source struct {
	Name string
	URL  string
}

// sourcesFlag implements flag.Value to support repeatable `-source` arguments.
type sourcesFlag []source

// String formats the flag value for help output.
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

// Set appends a parsed `name=url` (or plain `url`) source to the slice.
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

// inferSourceName derives a stable human-friendly name from a URL/path.
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

// domainsFlag implements flag.Value to support repeatable domain arguments.
type domainsFlag []string

// String formats the flag value for help output.
func (f *domainsFlag) String() string {
	if f == nil || len(*f) == 0 {
		return ""
	}
	return strings.Join(*f, ", ")
}

// Set appends a domain string to the slice (normalization happens later).
func (f *domainsFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("empty domain")
	}
	*f = append(*f, v)
	return nil
}

// main is the CLI entrypoint for rulegen.
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
	flag.BoolVar(&opts.FollowIncludes, "follow-includes", true, "expand !#include directives in filter lists (best-effort)")
	flag.IntVar(&opts.MaxIncludeDepth, "max-include-depth", 3, "maximum recursion depth for !#include expansion (0 disables)")
	flag.IntVar(&opts.MaxIncludes, "max-includes", 50, "maximum number of included files to fetch per source (0 disables)")
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

// run performs end-to-end rule generation: fetch sources, parse rules, convert to
// DNR candidates, finalize/deduplicate, and write JSON shards.
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
	if opts.MaxIncludeDepth < 0 {
		return fmt.Errorf("max-include-depth must be >= 0, got %d", opts.MaxIncludeDepth)
	}
	if opts.MaxIncludes < 0 {
		return fmt.Errorf("max-includes must be >= 0, got %d", opts.MaxIncludes)
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
		body, err := fetchSourceExpanded(ctx, client, src.URL, opts.FollowIncludes, opts.MaxIncludeDepth, opts.MaxIncludes)
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
			Priority:   4,
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

// excludedResourceTypes returns the default excluded resourceTypes list used by
// dynamic rules (when the caller wants to avoid main_frame matches).
func excludedResourceTypes(excludeMainFrame bool) []string {
	if !excludeMainFrame {
		return nil
	}
	return []string{"main_frame"}
}

// fetchSource retrieves a filter list from a URL or local file path.
//
// Supported inputs:
//   - local paths (relative/absolute)
//   - file:// URLs
//   - http(s):// URLs
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

// looksLikeFilePath returns true when s is an obvious filesystem path (not a URL).
func looksLikeFilePath(s string) bool {
	// Heuristic: treat obvious relative/absolute paths as files.
	return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "/")
}

// fetchSourceExpanded fetches a source and optionally expands `!#include ...`
// directives (best-effort) before returning the combined body.
func fetchSourceExpanded(ctx context.Context, client *http.Client, raw string, followIncludes bool, maxDepth, maxIncludes int) ([]byte, error) {
	body, err := fetchSource(ctx, client, raw)
	if err != nil {
		return nil, err
	}
	if !followIncludes || maxDepth <= 0 || maxIncludes <= 0 {
		return body, nil
	}
	visited := map[string]struct{}{raw: {}}
	return expandIncludes(ctx, client, raw, body, maxDepth, maxIncludes, visited)
}

// expandIncludes appends bodies referenced by `!#include ...` directives found in
// body, resolving include paths relative to baseRaw.
//
// Includes are appended to the end of the body (no attempt is made to preserve
// original ordering semantics), because the goal is to maximize usable network
// rules while keeping parsing conservative.
func expandIncludes(ctx context.Context, client *http.Client, baseRaw string, body []byte, maxDepth, maxIncludes int, visited map[string]struct{}) ([]byte, error) {
	if maxDepth <= 0 || maxIncludes <= 0 {
		return body, nil
	}

	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	var includeTargets []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "!#include") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "!#include"))
		if rest == "" {
			continue
		}
		rest = strings.Fields(rest)[0]
		target, err := resolveIncludeTarget(baseRaw, rest)
		if err != nil {
			continue
		}
		if _, ok := visited[target]; ok {
			continue
		}
		visited[target] = struct{}{}
		includeTargets = append(includeTargets, target)
		if len(includeTargets) >= maxIncludes {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(includeTargets) == 0 {
		return body, nil
	}

	var out bytes.Buffer
	out.Grow(len(body) + 1)
	out.Write(body)
	out.WriteByte('\n')

	for _, t := range includeTargets {
		incBody, err := fetchSource(ctx, client, t)
		if err != nil {
			continue
		}
		incBody, err = expandIncludes(ctx, client, t, incBody, maxDepth-1, maxIncludes, visited)
		if err != nil {
			continue
		}
		out.Write(incBody)
		out.WriteByte('\n')
	}

	return out.Bytes(), nil
}

// resolveIncludeTarget resolves an include path against a base source reference
// (URL or local path) and returns an absolute URL/path suitable for fetchSource.
func resolveIncludeTarget(baseRaw, include string) (string, error) {
	include = strings.TrimSpace(include)
	if include == "" {
		return "", errors.New("empty include")
	}

	// If include is an absolute URL, use it as-is.
	if u, err := url.Parse(include); err == nil && u.Scheme != "" {
		return include, nil
	}

	// File base.
	if looksLikeFilePath(baseRaw) {
		return filepath.Join(filepath.Dir(baseRaw), include), nil
	}
	if bu, err := url.Parse(baseRaw); err == nil {
		switch bu.Scheme {
		case "file":
			basePath := filepath.FromSlash(bu.Path)
			return filepath.Join(filepath.Dir(basePath), include), nil
		case "http", "https":
			rel, err := url.Parse(include)
			if err != nil {
				return "", err
			}
			return bu.ResolveReference(rel).String(), nil
		default:
			// If base isn't a known URL scheme, treat as a path.
			if bu.Scheme == "" {
				return filepath.Join(filepath.Dir(baseRaw), include), nil
			}
		}
	}

	// Last resort: treat include as a path.
	return include, nil
}

// parseStats describes how many lines were ignored, parsed, or unsupported.
type parseStats struct {
	LinesTotal       int
	LinesIgnored     int
	RulesParsed      int
	LinesUnsupported int

	ParsedByFormat      map[string]int
	UnsupportedByReason map[string]int
}

// abpRule is a parsed subset of ABP network-filtering rules.
// We only keep rules we can conservatively translate to DNR.
type abpRule struct {
	Exception bool
	Host      string // optional (normalized); used for allow/deny safety checks
	Path      string // only for domain-anchored rules
	URLFilter string // DNR urlFilter for patterns that don’t map to Host/Path
	Options   abpOptions
}

// abpOptions is the subset of ABP/AdGuard rule options understood by rulegen.
type abpOptions struct {
	DomainType               string   // "firstParty" or "thirdParty"
	ResourceTypes            []string // DNR resourceTypes
	ExcludedResourceTypes    []string
	InitiatorDomains         []string
	ExcludedInitiatorDomains []string

	// Important raises block rule priority (within static rules) when expressible.
	Important bool

	// MatchCase requests case-sensitive matching for urlFilter-based rules.
	MatchCase bool
}

// parseABPList parses an input list into a slice of conservatively-translatable
// network rules.
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
			strings.HasPrefix(line, "#") || // comment (common in hosts/DNS lists)
			strings.HasPrefix(line, "[") { // metadata section
			stats.LinesIgnored++
			continue
		}
		// Cosmetic filtering is not expressible in DNR.
		if isCosmeticRuleLine(line) {
			stats.LinesIgnored++
			continue
		}

		res := parseFilterLine(line)
		switch res.Kind {
		case lineIgnored:
			stats.LinesIgnored++
			continue
		case lineUnsupported:
			stats.LinesUnsupported++
			if stats.UnsupportedByReason == nil {
				stats.UnsupportedByReason = make(map[string]int)
			}
			stats.UnsupportedByReason[res.Reason]++
			continue
		case lineParsed:
			// ok
		default:
			stats.LinesUnsupported++
			if stats.UnsupportedByReason == nil {
				stats.UnsupportedByReason = make(map[string]int)
			}
			stats.UnsupportedByReason["internal_unknown_parse_kind"]++
			continue
		}

		stats.RulesParsed += len(res.Rules)
		if stats.ParsedByFormat == nil {
			stats.ParsedByFormat = make(map[string]int)
		}
		stats.ParsedByFormat[res.Format] += len(res.Rules)
		rules = append(rules, res.Rules...)
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

// lineParseKind classifies how a single input line was handled.
type lineParseKind uint8

const (
	// lineIgnored indicates the input line should not contribute any rules.
	lineIgnored lineParseKind = iota

	// lineParsed indicates the input line produced one or more rules.
	lineParsed

	// lineUnsupported indicates the line appears to be a rule, but rulegen chose
	// to skip it due to unsupported/ambiguous semantics.
	lineUnsupported
)

// lineParseResult is the result of parsing a single input line.
type lineParseResult struct {
	Kind   lineParseKind
	Rules  []abpRule
	Format string
	Reason string
}

// parseFilterLine parses a single line from a "canonical ad list" into zero or
// more abpRule entries.
//
// Supported inputs include:
//   - ABP/AdGuard network filters (a conservative subset)
//   - hosts-file lines (0.0.0.0 example.com)
//   - plain domain lines (example.com)
func parseFilterLine(line string) lineParseResult {
	// 1) Hosts-file style lines: "0.0.0.0 example.com example.net"
	if domains, ok := parseHostsDomains(line); ok {
		out := make([]abpRule, 0, len(domains))
		for _, d := range domains {
			out = append(out, abpRule{Host: d})
		}
		return lineParseResult{Kind: lineParsed, Rules: out, Format: "hosts"}
	}

	// 2) Domain-only lists: "example.com" or "example.com # comment"
	if d, ok := parseDomainOnlyLine(line); ok {
		return lineParseResult{Kind: lineParsed, Rules: []abpRule{{Host: d}}, Format: "domain"}
	}

	// 3) ABP/AdGuard network filter rules.
	if r, kind, reason := parseABPLine(line); kind != lineIgnored {
		switch kind {
		case lineParsed:
			return lineParseResult{Kind: lineParsed, Rules: []abpRule{r}, Format: "abp"}
		case lineUnsupported:
			return lineParseResult{Kind: lineUnsupported, Reason: reason, Format: "abp"}
		}
	}

	// Unknown syntax: treat as unsupported so users can see coverage gaps.
	return lineParseResult{Kind: lineUnsupported, Reason: "unrecognized_syntax"}
}

// isCosmeticRuleLine reports whether line looks like a cosmetic/snippet rule
// which cannot be expressed using Chrome DNR.
func isCosmeticRuleLine(line string) bool {
	// ABP / uBO / AdGuard cosmetic rule markers.
	// This is intentionally a bit broad: if a line contains one of these markers,
	// it's almost certainly cosmetic/snippet filtering.
	return strings.Contains(line, "##") ||
		strings.Contains(line, "#@#") ||
		strings.Contains(line, "#$#") ||
		strings.Contains(line, "#@#$#") ||
		strings.Contains(line, "#%#") ||
		strings.Contains(line, "#@%#")
}

// parseHostsDomains parses a hosts-file entry and returns the normalized domains
// it maps (e.g. "0.0.0.0 ads.example.com tracker.example.net").
func parseHostsDomains(line string) ([]string, bool) {
	// Strip inline comments (hosts files commonly use "#").
	if before, _, ok := strings.Cut(line, "#"); ok {
		line = before
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, false
	}
	ip := net.ParseIP(fields[0])
	if ip == nil {
		return nil, false
	}
	var out []string
	for _, f := range fields[1:] {
		if d := normalizeDomain(f); d != "" {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	out = normalizeDomains(out)
	return out, true
}

// parseDomainOnlyLine parses a single domain from a plain domain list line.
func parseDomainOnlyLine(line string) (string, bool) {
	// Strip inline comments.
	if before, _, ok := strings.Cut(line, "#"); ok {
		line = before
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	// Do not treat ABP-style patterns as domain-only.
	if strings.ContainsAny(line, "*^|/$") {
		return "", false
	}
	d := normalizeDomain(line)
	if d == "" || !strings.Contains(d, ".") {
		return "", false
	}
	return d, true
}

// parseABPLine parses a single ABP/AdGuard network-filter rule line into an
// abpRule, returning whether it was parsed, ignored, or treated as unsupported.
func parseABPLine(line string) (abpRule, lineParseKind, string) {
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

	if opts != "" {
		o, kind, reason := parseABPOptions(opts)
		switch kind {
		case optionsOK:
			// ok
		case optionsSkip:
			// "badfilter" or non-network-only modifiers indicate the rule should not apply.
			return abpRule{}, lineIgnored, ""
		case optionsUnsupported:
			return abpRule{}, lineUnsupported, reason
		default:
			return abpRule{}, lineUnsupported, "internal_unknown_options_kind"
		}
		r.Options = o
	}

	host, path, urlFilter, ok := parseABPPattern(pattern)
	if !ok {
		return abpRule{}, lineUnsupported, "unsupported_pattern"
	}

	if host != "" {
		// Conservative safety: do not attempt to translate patterns with host wildcards
		// or unusual characters when we can extract a host.
		if strings.ContainsAny(host, "*^") {
			return abpRule{}, lineUnsupported, "unsupported_host_wildcard"
		}
		host = normalizeDomain(host)
		if host == "" {
			return abpRule{}, lineUnsupported, "invalid_host"
		}
		r.Host = host
	}

	path = strings.ReplaceAll(path, "^", "*")
	urlFilter = strings.ReplaceAll(urlFilter, "^", "*")

	r.Path = path
	r.URLFilter = urlFilter
	return r, lineParsed, ""
}

// optionsParseKind is the classification result for an ABP options string.
type optionsParseKind uint8

const (
	// optionsOK indicates options were parsed and are supported.
	optionsOK optionsParseKind = iota

	// optionsSkip indicates the rule should not apply (e.g. badfilter or cosmetic-only).
	optionsSkip

	// optionsUnsupported indicates the rule uses modifiers with semantics rulegen
	// cannot safely translate to DNR.
	optionsUnsupported
)

// parseABPOptions parses a comma-delimited ABP/AdGuard options string into a subset
// of DNR-compatible fields.
//
// It is conservative: options with semantics we can't represent (redirect, csp,
// removeparam, ...) are treated as unsupported.
func parseABPOptions(opts string) (abpOptions, optionsParseKind, string) {
	var o abpOptions
	var unsupported []string

	for _, raw := range strings.Split(opts, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if raw == "badfilter" {
			return abpOptions{}, optionsSkip, ""
		}

		switch raw {
		case "third-party", "3p":
			o.DomainType = "thirdParty"
			continue
		case "~third-party", "1p":
			o.DomainType = "firstParty"
			continue
		case "first-party":
			o.DomainType = "firstParty"
			continue
		case "~first-party":
			o.DomainType = "thirdParty"
			continue
		case "important":
			o.Important = true
			continue
		case "match-case":
			o.MatchCase = true
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
				unsupported = append(unsupported, raw)
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

		// Cosmetic-only modifiers: ignore the whole rule (it doesn't affect network
		// requests) rather than classifying it as "unsupported".
		switch name {
		case "elemhide", "ehide", "generichide", "ghide", "specifichide", "shide":
			return abpOptions{}, optionsSkip, ""
		}

		// Many options exist; be conservative and skip rules we can’t interpret.
		unsupported = append(unsupported, raw)
	}

	o.ResourceTypes = normalizeEnumList(o.ResourceTypes)
	o.ExcludedResourceTypes = normalizeEnumList(o.ExcludedResourceTypes)
	o.InitiatorDomains = normalizeDomains(o.InitiatorDomains)
	o.ExcludedInitiatorDomains = normalizeDomains(o.ExcludedInitiatorDomains)

	// DNR requires only one of resourceTypes/excludedResourceTypes.
	if len(o.ResourceTypes) != 0 && len(o.ExcludedResourceTypes) != 0 {
		return abpOptions{}, optionsUnsupported, "resource_types_and_excluded"
	}

	if len(unsupported) != 0 {
		return abpOptions{}, optionsUnsupported, "unsupported_option"
	}

	return o, optionsOK, ""
}

// parseABPDomainList parses ABP's `domain=` option value into include and exclude
// domain lists.
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

// abpResourceTypeToDNR maps ABP/AdGuard resource type modifiers to DNR resourceTypes.
func abpResourceTypeToDNR(opt string) (string, bool) {
	switch opt {
	case "document":
		return "main_frame", true
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
	case "frame":
		return "sub_frame", true
	case "xhr":
		return "xmlhttprequest", true
	default:
		return "", false
	}
}

// parseABPPattern parses an ABP "pattern" string and returns either:
//   - (host, path, "", true) for domain-anchored rules of the form `||host...`
//   - ("", "", urlFilter, true) for patterns we can only represent as urlFilter
//
// The returned values are later normalized/canonicalized by callers.
func parseABPPattern(pattern string) (host, path, urlFilter string, ok bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", "", "", false
	}

	// We only translate a subset of ABP patterns:
	// - "||host^" or "||host/path"
	// - full URL patterns "https://host/path" (best-effort; preserves wildcards)
	if strings.HasPrefix(pattern, "||") {
		s := strings.TrimPrefix(pattern, "||")
		if s == "" {
			return "", "", "", false
		}
		i := strings.IndexAny(s, "^/?")
		if i == -1 {
			return s, "", "", true
		}
		host = s[:i]
		delim := s[i]
		rest := s[i:]
		switch delim {
		case '^':
			// `^` is a separator wildcard. If the rule continues with a path/query,
			// preserve that to keep the rule high-signal.
			if len(rest) >= 2 && (rest[1] == '/' || rest[1] == '?') {
				return host, rest[1:], "", true
			}
			return host, "", "", true
		case '/', '?':
			return host, rest, "", true
		default:
			return "", "", "", false
		}
	}

	trimmed := strings.TrimLeft(pattern, "|")
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		urlFilter = pattern
		host = hostFromSchemeURLPattern(urlFilter)
		return host, "", urlFilter, true
	}

	return "", "", "", false
}

// normalizeDomain normalizes a domain-like string for use in DNR fields.
func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return ""
	}
	// Drop an explicit port (common when users paste hosts like "example.com:443").
	if before, after, ok := strings.Cut(d, ":"); ok && after != "" {
		allDigits := true
		for i := 0; i < len(after); i++ {
			if after[i] < '0' || after[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			d = before
		}
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

// hostFromSchemeURLPattern extracts a literal host from a scheme+host urlFilter
// pattern (e.g. `|https://example.com/path`), returning "" if it can't.
func hostFromSchemeURLPattern(pat string) string {
	// Extract a literal host from patterns like:
	//   |https://example.com/path
	//   https://example.com/path
	// If the host contains wildcards, return "".
	s := strings.TrimLeft(strings.TrimSpace(pat), "|")
	if !(strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) {
		return ""
	}
	afterScheme := strings.SplitN(s, "://", 2)
	if len(afterScheme) != 2 {
		return ""
	}
	rest := afterScheme[1]
	hostPort := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hostPort = rest[:i]
	}
	if hostPort == "" || strings.Contains(hostPort, "*") {
		return ""
	}
	// Drop port, if any.
	host := hostPort
	if h, _, ok := strings.Cut(hostPort, ":"); ok {
		host = h
	}
	return normalizeDomain(host)
}

// normalizeDomains normalizes, deduplicates, and sorts a set of domains.
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

// normalizeEnumList sorts and deduplicates an enum list (resource types, etc).
func normalizeEnumList(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := slices.Clone(xs)
	slices.Sort(out)
	out = slices.Compact(out)
	return out
}

// convertStats summarizes conversion from parsed rules into DNR rule candidates.
type convertStats struct {
	ParsedTotal int

	ConvertedBlocks     int
	ConvertedExceptions int

	SkippedAllowlisted int
	SkippedTooLong     int
	SkippedMainFrame   int

	SkippedExceptionsMode       int
	SkippedExceptionsUnscoped   int
	SkippedExceptionsDenylisted int
}

// ruleCandidate is an intermediate form used for deduplication and sorting
// before producing final DNR JSON rules.
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

// action matches the DNR ruleset schema.
type action struct {
	Type string `json:"type"`
}

// condition matches the DNR ruleset schema.
type condition struct {
	URLFilter                string   `json:"urlFilter,omitempty"`
	IsURLFilterCaseSensitive *bool    `json:"isUrlFilterCaseSensitive,omitempty"`
	RequestDomains           []string `json:"requestDomains,omitempty"`
	ExcludedRequestDomains   []string `json:"excludedRequestDomains,omitempty"`
	DomainType               string   `json:"domainType,omitempty"`
	ResourceTypes            []string `json:"resourceTypes,omitempty"`
	ExcludedResourceTypes    []string `json:"excludedResourceTypes,omitempty"`
	InitiatorDomains         []string `json:"initiatorDomains,omitempty"`
	ExcludedInitiatorDomains []string `json:"excludedInitiatorDomains,omitempty"`
}

// convertABPRules converts parsed rules into DNR rule candidates, applying
// safety/compatibility policies (allowlists, denylist, exception emission mode).
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
		// Skip main_frame matching rules unless explicitly enabled.
		if excludeMainFrame && slices.Contains(r.Options.ResourceTypes, "main_frame") {
			stats.SkippedMainFrame++
			continue
		}

		hostForSafety := r.Host
		if hostForSafety == "" && r.URLFilter != "" {
			// Best-effort host extraction for allow/deny safety checks.
			hostForSafety = urlFilterHostAny(r.URLFilter)
		}

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
			if hostForSafety != "" && isAllowlistedDomain(hostForSafety, exceptionDenySet) {
				stats.SkippedExceptionsDenylisted++
				continue
			}
		} else {
			if hostForSafety != "" && isAllowlistedDomain(hostForSafety, allowSet) {
				stats.SkippedAllowlisted++
				continue
			}
		}

		filter := r.URLFilter
		if filter == "" {
			filter = urlFilterForDomain(r.Host, r.Path)
		}
		if len(filter) > 1024 {
			stats.SkippedTooLong++
			continue
		}

		c := condition{
			URLFilter:                filter,
			RequestDomains:           nil,
			DomainType:               r.Options.DomainType,
			ResourceTypes:            slices.Clone(r.Options.ResourceTypes),
			ExcludedResourceTypes:    slices.Clone(r.Options.ExcludedResourceTypes),
			InitiatorDomains:         slices.Clone(r.Options.InitiatorDomains),
			ExcludedInitiatorDomains: slices.Clone(r.Options.ExcludedInitiatorDomains),
		}
		if r.Options.MatchCase && c.URLFilter != "" {
			v := true
			c.IsURLFilterCaseSensitive = &v
		}
		c = applyResourceTypePolicy(c, excludeMainFrame)

		if r.URLFilter == "" && r.Path == "" && r.Host != "" {
			// For simple host-anchored rules, prefer requestDomains for correctness and
			// smaller rules.
			c.URLFilter = ""
			c.IsURLFilterCaseSensitive = nil
			c.RequestDomains = []string{r.Host}
		}
		c = canonicalizeCondition(c)

		actionType := "block"
		priority := 1
		if r.Exception {
			actionType = "allow"
			priority = 3
		} else if r.Options.Important {
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

// canonicalizeCondition normalizes and sorts condition lists for stable
// deduplication and deterministic output.
func canonicalizeCondition(c condition) condition {
	c.RequestDomains = normalizeDomains(c.RequestDomains)
	c.ExcludedRequestDomains = normalizeDomains(c.ExcludedRequestDomains)
	c.ResourceTypes = normalizeEnumList(c.ResourceTypes)
	c.ExcludedResourceTypes = normalizeEnumList(c.ExcludedResourceTypes)
	c.InitiatorDomains = normalizeDomains(c.InitiatorDomains)
	c.ExcludedInitiatorDomains = normalizeDomains(c.ExcludedInitiatorDomains)
	return c
}

// applyResourceTypePolicy enforces DNR constraints and default safety behavior
// around main_frame.
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
		// ResourceTypes is an explicit allowlist; do not try to "inject" main_frame
		// exclusions here (the caller enforces main_frame policy separately).
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

// urlFilterForDomain builds a DNR urlFilter that matches a domain (and its
// subdomains) and optionally a path prefix.
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

// isAllowlistedDomain reports whether domain matches an entry in allowSet, either
// exactly or as a subdomain of an allowlisted base domain.
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

// finalizeRules deduplicates/sorts candidates and converts them into final DNR
// JSON rules with deterministic IDs, capped to maxRules.
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

// rulesFromCandidates assigns sequential IDs (starting at 1) and converts rule
// candidates into DNR schema rules.
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

// finalizeCandidates canonicalizes, deduplicates, and sorts candidates into a
// deterministic order before sharding/capping.
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

// urlFilterHost extracts the host from a DNR urlFilter of the form `||host/...`.
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

// urlFilterHostAny extracts a host from either a `||host/...` urlFilter or a
// scheme URL pattern (e.g. `|https://host/...`), returning "" if unknown.
func urlFilterHostAny(f string) string {
	if h := urlFilterHost(f); h != "" {
		return h
	}
	return hostFromSchemeURLPattern(f)
}

// conditionHost extracts a representative host from a DNR condition for sorting
// and frequency heuristics.
func conditionHost(c condition) string {
	if h := urlFilterHostAny(c.URLFilter); h != "" {
		return h
	}
	if len(c.RequestDomains) == 1 {
		return c.RequestDomains[0]
	}
	return ""
}

// baseDomain returns the last two labels of host (best-effort), used only for
// heuristic sorting.
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

// cmpDesc compares integers for descending sort order.
func cmpDesc(a, b int) int {
	if a == b {
		return 0
	}
	if a > b {
		return -1
	}
	return 1
}

// cmpAsc compares integers for ascending sort order.
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

// candidateKey returns a stable string key for deduplicating rule candidates.
func candidateKey(c ruleCandidate) (string, error) {
	cond := canonicalizeCondition(c.Condition)
	b, err := json.Marshal(cond)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s|%d|%s", c.ActionType, c.Priority, string(b)), nil
}

// writeRulesJSONAtomic writes rules to path as indented JSON, using a temp file
// + atomic rename for crash-safety.
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

// printStats prints a human-readable summary of parsing and conversion.
func printStats(w io.Writer, sources []source, parseBySource map[string]parseStats, conv convertStats, totalBlocks, totalExceptions, totalAllowlist, blockShards int) {
	fmt.Fprintf(w, "rulegen: generated blocks=%d (shards=%d) exceptions=%d allowlist=%d\n", totalBlocks, blockShards, totalExceptions, totalAllowlist)
	for _, src := range sources {
		if st, ok := parseBySource[src.Name]; ok {
			fmt.Fprintf(w, "  %s: lines=%d rules=%d unsupported_lines=%d ignored_lines=%d\n",
				src.Name, st.LinesTotal, st.RulesParsed, st.LinesUnsupported, st.LinesIgnored)
			if len(st.ParsedByFormat) != 0 {
				var keys []string
				for k := range st.ParsedByFormat {
					keys = append(keys, k)
				}
				slices.Sort(keys)
				var parts []string
				for _, k := range keys {
					parts = append(parts, fmt.Sprintf("%s=%d", k, st.ParsedByFormat[k]))
				}
				fmt.Fprintf(w, "    formats: %s\n", strings.Join(parts, " "))
			}
		}
	}
	fmt.Fprintf(w, "  converted: blocks=%d exceptions=%d skipped_allowlisted=%d skipped_toolong=%d\n",
		conv.ConvertedBlocks, conv.ConvertedExceptions, conv.SkippedAllowlisted, conv.SkippedTooLong)
	fmt.Fprintf(w, "  exceptions: skipped_mode=%d skipped_unscoped=%d skipped_denylisted=%d\n",
		conv.SkippedExceptionsMode, conv.SkippedExceptionsUnscoped, conv.SkippedExceptionsDenylisted)
	fmt.Fprintf(w, "  policy: skipped_main_frame=%d\n", conv.SkippedMainFrame)
}

// shardPaths returns the output paths for a sharded ruleset, preserving the
// original out path as shard 1 and appending ".N" before the extension for
// additional shards.
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

// splitCandidates splits candidates into at most shards slices, each with at most
// maxPerShard elements, preserving order.
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
