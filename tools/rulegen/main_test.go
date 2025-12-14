package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInferSourceName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com/easylist.txt", "easylist"},
		{"https://example.com/dir/list.txt", "list"},
		{"https://easylist.to/", "easylist_to"},
		{"./lists/my.list.txt", "my.list"},
		{"/tmp/ads.txt", "ads"},
		{"weird", "weird"},
	}
	for _, tt := range tests {
		if got := inferSourceName(tt.in); got != tt.want {
			t.Fatalf("inferSourceName(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestSourcesFlagSet(t *testing.T) {
	t.Parallel()
	var f sourcesFlag
	if err := f.Set("my=https://example.com/list.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("https://example.com/other.txt"); err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 {
		t.Fatalf("len=%d", len(f))
	}
	if f[0].Name != "my" || f[0].URL != "https://example.com/list.txt" {
		t.Fatalf("first=%+v", f[0])
	}
	if f[1].Name != "other" || f[1].URL != "https://example.com/other.txt" {
		t.Fatalf("second=%+v", f[1])
	}
}

func TestDomainsFlagSet(t *testing.T) {
	t.Parallel()
	var f domainsFlag
	if err := f.Set("example.com"); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("  foo.com "); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f, ",") != "example.com,foo.com" {
		t.Fatalf("domains=%v", []string(f))
	}
}

func TestLooksLikeFilePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"./a.txt", true},
		{"../a.txt", true},
		{"/tmp/a.txt", true},
		{"https://example.com/a.txt", false},
		{"file:///tmp/a.txt", false},
		{"relative.txt", false},
	}
	for _, tt := range tests {
		if got := looksLikeFilePath(tt.in); got != tt.want {
			t.Fatalf("looksLikeFilePath(%q)=%v want %v", tt.in, got, tt.want)
		}
	}
}

func TestExcludedResourceTypes(t *testing.T) {
	t.Parallel()
	if got := excludedResourceTypes(false); got != nil {
		t.Fatalf("got=%v", got)
	}
	got := excludedResourceTypes(true)
	if strings.Join(got, ",") != "main_frame" {
		t.Fatalf("got=%v", got)
	}
}

func TestParseABPLine_BasicBlock(t *testing.T) {
	r, kind, reason := parseABPLine("||doubleclick.net^")
	if kind != lineParsed {
		t.Fatalf("kind=%v reason=%q", kind, reason)
	}
	if r.Exception {
		t.Fatalf("expected block rule")
	}
	if r.Host != "doubleclick.net" {
		t.Fatalf("host=%q", r.Host)
	}
	if r.Path != "" {
		t.Fatalf("path=%q", r.Path)
	}
}

func TestParseABPLine_Exception(t *testing.T) {
	r, kind, reason := parseABPLine("@@||example.com^")
	if kind != lineParsed {
		t.Fatalf("kind=%v reason=%q", kind, reason)
	}
	if !r.Exception {
		t.Fatalf("expected exception")
	}
	if r.Host != "example.com" {
		t.Fatalf("host=%q", r.Host)
	}
}

func TestParseABPLine_OptionsThirdPartyAndTypes(t *testing.T) {
	r, kind, reason := parseABPLine("||example.com^$third-party,script,xmlhttprequest")
	if kind != lineParsed {
		t.Fatalf("kind=%v reason=%q", kind, reason)
	}
	if r.Options.DomainType != "thirdParty" {
		t.Fatalf("domainType=%q", r.Options.DomainType)
	}
	if strings.Join(r.Options.ResourceTypes, ",") != "script,xmlhttprequest" {
		t.Fatalf("resourceTypes=%v", r.Options.ResourceTypes)
	}
}

func TestParseABPLine_DomainOptionToInitiatorDomains(t *testing.T) {
	r, kind, reason := parseABPLine("||tracker.example^$domain=foo.com|~bar.com,script")
	if kind != lineParsed {
		t.Fatalf("kind=%v reason=%q", kind, reason)
	}
	if strings.Join(r.Options.InitiatorDomains, ",") != "foo.com" {
		t.Fatalf("initiatorDomains=%v", r.Options.InitiatorDomains)
	}
	if strings.Join(r.Options.ExcludedInitiatorDomains, ",") != "bar.com" {
		t.Fatalf("excludedInitiatorDomains=%v", r.Options.ExcludedInitiatorDomains)
	}
}

func TestParseABPLine_UnsupportedOptionSkips(t *testing.T) {
	_, kind, reason := parseABPLine("||example.com^$redirect=noopjs")
	if kind != lineUnsupported {
		t.Fatalf("kind=%v reason=%q", kind, reason)
	}
}

func TestParseFilterLine_DomainOnly(t *testing.T) {
	res := parseFilterLine("example.com")
	if res.Kind != lineParsed {
		t.Fatalf("kind=%v reason=%q", res.Kind, res.Reason)
	}
	if res.Format != "domain" {
		t.Fatalf("format=%q", res.Format)
	}
	if len(res.Rules) != 1 || res.Rules[0].Host != "example.com" {
		t.Fatalf("rules=%v", res.Rules)
	}
}

func TestParseFilterLine_HostsMultipleDomains(t *testing.T) {
	res := parseFilterLine("0.0.0.0 ads.example.com tracker.example.net # comment")
	if res.Kind != lineParsed {
		t.Fatalf("kind=%v reason=%q", res.Kind, res.Reason)
	}
	if res.Format != "hosts" {
		t.Fatalf("format=%q", res.Format)
	}
	if got := strings.Join([]string{res.Rules[0].Host, res.Rules[1].Host}, ","); got != "ads.example.com,tracker.example.net" {
		t.Fatalf("hosts=%s", got)
	}
}

func TestParseHostsDomains_NotHostsLine(t *testing.T) {
	t.Parallel()
	if _, ok := parseHostsDomains("not an ip example.com"); ok {
		t.Fatalf("expected ok=false")
	}
}

func TestParseABPOptions_SkipBadfilter(t *testing.T) {
	t.Parallel()
	_, kind, _ := parseABPOptions("badfilter")
	if kind != optionsSkip {
		t.Fatalf("kind=%v", kind)
	}
}

func TestParseABPOptions_Unsupported(t *testing.T) {
	t.Parallel()
	_, kind, reason := parseABPOptions("redirect=noopjs")
	if kind != optionsUnsupported || reason == "" {
		t.Fatalf("kind=%v reason=%q", kind, reason)
	}
}

func TestParseABPDomainList(t *testing.T) {
	t.Parallel()
	inc, exc := parseABPDomainList("foo.com|~bar.com,baz.com")
	if strings.Join(inc, ",") != "foo.com,baz.com" {
		t.Fatalf("include=%v", inc)
	}
	if strings.Join(exc, ",") != "bar.com" {
		t.Fatalf("exclude=%v", exc)
	}
}

func TestAbpResourceTypeToDNR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"script", "script", true},
		{"xhr", "xmlhttprequest", true},
		{"document", "main_frame", true},
		{"subdocument", "sub_frame", true},
		{"frame", "sub_frame", true},
		{"nope", "", false},
	}
	for _, tt := range tests {
		got, ok := abpResourceTypeToDNR(tt.in)
		if ok != tt.wantOK || got != tt.want {
			t.Fatalf("abpResourceTypeToDNR(%q)=(%q,%v) want (%q,%v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestURLFilterForDomain(t *testing.T) {
	got := urlFilterForDomain("example.com", "/path")
	want := "||example.com/path*"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseABPPattern_HostBoundaryThenPath(t *testing.T) {
	host, path, urlFilter, ok := parseABPPattern("||example.com^/ads.js")
	if !ok {
		t.Fatalf("expected ok")
	}
	if host != "example.com" {
		t.Fatalf("host=%q", host)
	}
	if path != "/ads.js" {
		t.Fatalf("path=%q", path)
	}
	if urlFilter != "" {
		t.Fatalf("urlFilter=%q", urlFilter)
	}
}

func TestParseABPPattern_URLPatternPreserved(t *testing.T) {
	t.Parallel()
	host, path, urlFilter, ok := parseABPPattern("|https://example.com/ads/*")
	if !ok {
		t.Fatalf("expected ok")
	}
	if host != "example.com" {
		t.Fatalf("host=%q", host)
	}
	if path != "" {
		t.Fatalf("path=%q", path)
	}
	if urlFilter != "|https://example.com/ads/*" {
		t.Fatalf("urlFilter=%q", urlFilter)
	}
}

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"Example.COM", "example.com"},
		{".example.com.", "example.com"},
		{"example.com:443", "example.com"},
		{"127.0.0.1", ""},
		{"exa mple.com", ""},
		{"example.com/path", ""},
	}
	for _, tt := range tests {
		if got := normalizeDomain(tt.in); got != tt.want {
			t.Fatalf("normalizeDomain(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestHostFromSchemeURLPattern(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"|https://example.com/path", "example.com"},
		{"https://example.com:8443/path", "example.com"},
		{"|https://*.example.com/path", ""},
		{"||example.com^", ""},
	}
	for _, tt := range tests {
		if got := hostFromSchemeURLPattern(tt.in); got != tt.want {
			t.Fatalf("hostFromSchemeURLPattern(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeDomains(t *testing.T) {
	t.Parallel()
	got := normalizeDomains([]string{"Example.com", "example.com", "b.com", "a.com", ""})
	if strings.Join(got, ",") != "a.com,b.com,example.com" {
		t.Fatalf("got=%v", got)
	}
}

func TestNormalizeEnumList(t *testing.T) {
	t.Parallel()
	got := normalizeEnumList([]string{"b", "a", "a"})
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("got=%v", got)
	}
}

func TestCanonicalizeCondition(t *testing.T) {
	t.Parallel()
	c := canonicalizeCondition(condition{
		RequestDomains:           []string{"b.com", "a.com", "a.com"},
		ExcludedRequestDomains:   []string{"x.com", "x.com"},
		ResourceTypes:            []string{"script", "image", "image"},
		InitiatorDomains:         []string{"Site.com", "site.com"},
		ExcludedInitiatorDomains: []string{"b.com", "a.com"},
	})
	if strings.Join(c.RequestDomains, ",") != "a.com,b.com" {
		t.Fatalf("requestDomains=%v", c.RequestDomains)
	}
	if strings.Join(c.ResourceTypes, ",") != "image,script" {
		t.Fatalf("resourceTypes=%v", c.ResourceTypes)
	}
	if strings.Join(c.InitiatorDomains, ",") != "site.com" {
		t.Fatalf("initiatorDomains=%v", c.InitiatorDomains)
	}
}

func TestApplyResourceTypePolicy_ExcludedAddsMainFrame(t *testing.T) {
	t.Parallel()
	c := applyResourceTypePolicy(condition{ExcludedResourceTypes: []string{"image"}}, true)
	if !strings.Contains(strings.Join(c.ExcludedResourceTypes, ","), "main_frame") {
		t.Fatalf("excluded=%v", c.ExcludedResourceTypes)
	}
}

func TestApplyResourceTypePolicy_ResourceTypesUnchanged(t *testing.T) {
	t.Parallel()
	c := applyResourceTypePolicy(condition{ResourceTypes: []string{"image"}}, true)
	if strings.Join(c.ResourceTypes, ",") != "image" {
		t.Fatalf("resourceTypes=%v", c.ResourceTypes)
	}
	if len(c.ExcludedResourceTypes) != 0 {
		t.Fatalf("excludedResourceTypes=%v", c.ExcludedResourceTypes)
	}
}

func TestConvertABPRules_MatchCaseSetsDNRFlag(t *testing.T) {
	r, kind, reason := parseABPLine("||example.com^/Ads.js$match-case")
	if kind != lineParsed {
		t.Fatalf("kind=%v reason=%q", kind, reason)
	}
	blocks, _, _, err := convertABPRules([]abpRule{r}, map[string]struct{}{}, map[string]struct{}{}, "none", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 {
		t.Fatalf("blocks=%d", len(blocks))
	}
	if blocks[0].Condition.IsURLFilterCaseSensitive == nil || *blocks[0].Condition.IsURLFilterCaseSensitive != true {
		t.Fatalf("caseSensitive=%v", blocks[0].Condition.IsURLFilterCaseSensitive)
	}
}

func TestConvertABPRules_ImportantRaisesBlockPriorityButBelowAllow(t *testing.T) {
	r, kind, reason := parseABPLine("||example.com^/ads.js$important")
	if kind != lineParsed {
		t.Fatalf("kind=%v reason=%q", kind, reason)
	}
	blocks, _, _, err := convertABPRules([]abpRule{r}, map[string]struct{}{}, map[string]struct{}{}, "none", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 {
		t.Fatalf("blocks=%d", len(blocks))
	}
	if blocks[0].Priority != 2 {
		t.Fatalf("priority=%d", blocks[0].Priority)
	}
}

func TestConvertABPRules_AllowlistedSkipBlocks(t *testing.T) {
	allow := map[string]struct{}{"intercom.io": {}}
	blocks, exceptions, st, err := convertABPRules([]abpRule{{Host: "widget.intercom.io"}}, allow, map[string]struct{}{}, "none", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 0 || len(exceptions) != 0 {
		t.Fatalf("blocks=%d exceptions=%d", len(blocks), len(exceptions))
	}
	if st.SkippedAllowlisted != 1 {
		t.Fatalf("skipped=%d", st.SkippedAllowlisted)
	}
}

func TestConvertABPRules_ExplicitMainFrameSkippedByDefault(t *testing.T) {
	r := abpRule{
		Host: "example.com",
		Options: abpOptions{
			ResourceTypes: []string{"main_frame"},
		},
	}
	blocks, exceptions, st, err := convertABPRules([]abpRule{r}, map[string]struct{}{}, map[string]struct{}{}, "none", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 0 || len(exceptions) != 0 {
		t.Fatalf("blocks=%d exceptions=%d", len(blocks), len(exceptions))
	}
	if st.SkippedMainFrame != 1 {
		t.Fatalf("skippedMainFrame=%d", st.SkippedMainFrame)
	}
}

func TestIsAllowlistedDomain(t *testing.T) {
	t.Parallel()
	set := map[string]struct{}{"example.com": {}}
	if !isAllowlistedDomain("example.com", set) {
		t.Fatalf("expected exact match")
	}
	if !isAllowlistedDomain("a.example.com", set) {
		t.Fatalf("expected subdomain match")
	}
	if isAllowlistedDomain("evil.com", set) {
		t.Fatalf("expected false")
	}
}

func TestConvertABPRules_ExceptionsScopedSkipsUnscoped(t *testing.T) {
	blocks, exceptions, st, err := convertABPRules([]abpRule{{Exception: true, Host: "example.com"}}, map[string]struct{}{}, map[string]struct{}{}, "scoped", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 0 || len(exceptions) != 0 {
		t.Fatalf("blocks=%d exceptions=%d", len(blocks), len(exceptions))
	}
	if st.SkippedExceptionsUnscoped != 1 {
		t.Fatalf("skipped=%d", st.SkippedExceptionsUnscoped)
	}
}

func TestConvertABPRules_ExceptionsDenylistSkipsKnownTrackers(t *testing.T) {
	exc := abpRule{
		Exception: true,
		Host:      "g.doubleclick.net",
		Options: abpOptions{
			InitiatorDomains: []string{"example.com"},
		},
	}
	_, exceptions, st, err := convertABPRules([]abpRule{exc}, map[string]struct{}{}, map[string]struct{}{"doubleclick.net": {}}, "all", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(exceptions) != 0 {
		t.Fatalf("exceptions=%d", len(exceptions))
	}
	if st.SkippedExceptionsDenylisted != 1 {
		t.Fatalf("skipped=%d", st.SkippedExceptionsDenylisted)
	}
}

func TestFinalizeRules_DedupAndDeterministicIDs(t *testing.T) {
	c1 := ruleCandidate{
		ActionType: "block",
		Priority:   1,
		Condition:  condition{URLFilter: "*://*.a.com/*"},
	}
	c2 := c1

	rules, err := finalizeRules([]ruleCandidate{c1, c2}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d", len(rules))
	}
	if rules[0].ID != 1 {
		t.Fatalf("id=%d", rules[0].ID)
	}
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\"urlFilter\"") {
		t.Fatalf("expected marshaled rules to contain urlFilter")
	}
}

func TestCandidateKey_CanonicalizesLists(t *testing.T) {
	t.Parallel()
	a := ruleCandidate{
		ActionType: "block",
		Priority:   1,
		Condition: condition{
			RequestDomains: []string{"b.com", "a.com"},
			ResourceTypes:  []string{"script", "image"},
		},
	}
	b := ruleCandidate{
		ActionType: "block",
		Priority:   1,
		Condition: condition{
			RequestDomains: []string{"a.com", "b.com"},
			ResourceTypes:  []string{"image", "script"},
		},
	}
	ka, err := candidateKey(a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := candidateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if ka != kb {
		t.Fatalf("keys differ:\nA=%s\nB=%s", ka, kb)
	}
}

func TestURLFilterHostAny(t *testing.T) {
	t.Parallel()
	if got := urlFilterHostAny("||example.com/path*"); got != "example.com" {
		t.Fatalf("got=%q", got)
	}
	if got := urlFilterHostAny("|https://example.com/path*"); got != "example.com" {
		t.Fatalf("got=%q", got)
	}
	if got := urlFilterHostAny("*://*/*"); got != "" {
		t.Fatalf("got=%q", got)
	}
}

func TestBaseDomain(t *testing.T) {
	t.Parallel()
	if got := baseDomain("a.b.example.com"); got != "example.com" {
		t.Fatalf("got=%q", got)
	}
	if got := baseDomain("localhost"); got != "" {
		t.Fatalf("got=%q", got)
	}
}

func TestURLFilterBreadthScore(t *testing.T) {
	t.Parallel()
	if urlFilterBreadthScore("||example.com/") <= urlFilterBreadthScore("||example.com/ads*") {
		t.Fatalf("expected domain-only broader than path")
	}
}

func TestConditionSpecificityScore(t *testing.T) {
	t.Parallel()
	broad := condition{}
	narrow := condition{DomainType: "thirdParty", InitiatorDomains: []string{"a.com"}}
	if conditionSpecificityScore(broad) >= conditionSpecificityScore(narrow) {
		t.Fatalf("expected broad score < narrow score")
	}
}

func TestWriteRulesJSONAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.json")
	want := []rule{{ID: 1, Priority: 1, Action: action{Type: "block"}, Condition: condition{URLFilter: "||example.com/"}}}
	if err := writeRulesJSONAtomic(p, want); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []rule
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestPrintStats(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printStats(&buf,
		[]source{{Name: "s1", URL: "x"}},
		map[string]parseStats{
			"s1": {LinesTotal: 10, LinesIgnored: 2, RulesParsed: 3, LinesUnsupported: 5, ParsedByFormat: map[string]int{"abp": 3}},
		},
		convertStats{ConvertedBlocks: 1, ConvertedExceptions: 2},
		1, 2, 0, 1,
	)
	if !strings.Contains(buf.String(), "formats: abp=3") {
		t.Fatalf("missing formats: %s", buf.String())
	}
}

func TestShardPaths(t *testing.T) {
	t.Parallel()
	got, err := shardPaths("rules.json", 3)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "rules.json,rules.2.json,rules.3.json" {
		t.Fatalf("paths=%v", got)
	}
	if _, err := shardPaths("rules", 2); err == nil {
		t.Fatalf("expected error for no extension")
	}
}

func TestSplitCandidates(t *testing.T) {
	t.Parallel()
	in := []ruleCandidate{{}, {}, {}, {}, {}}
	out := splitCandidates(in, 2, 3)
	if len(out) != 3 {
		t.Fatalf("len=%d", len(out))
	}
	if len(out[0]) != 2 || len(out[1]) != 2 || len(out[2]) != 1 {
		t.Fatalf("sizes=%d,%d,%d", len(out[0]), len(out[1]), len(out[2]))
	}
}

func TestFetchSourceExpanded_FollowsIncludes_LocalFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(b, []byte("||b.example^"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, []byte("!#include b.txt\n||a.example^\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	body, err := fetchSourceExpanded(context.Background(), &http.Client{}, a, true, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	rules, st, err := parseABPList(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if st.RulesParsed != 2 || len(rules) != 2 {
		t.Fatalf("rulesParsed=%d len=%d", st.RulesParsed, len(rules))
	}
}

func TestFetchSource_LocalFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := fetchSource(context.Background(), &http.Client{}, p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatalf("got=%q", string(b))
	}
}

func TestExpandIncludes_MaxDepth(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	c := filepath.Join(dir, "c.txt")
	if err := os.WriteFile(c, []byte("||c.example^\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("!#include c.txt\n||b.example^\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, []byte("!#include b.txt\n||a.example^\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Depth=1: includes b but does not expand b's include of c.
	body, err := fetchSourceExpanded(context.Background(), &http.Client{}, a, true, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "||b.example^") {
		t.Fatalf("missing b: %q", s)
	}
	if strings.Contains(s, "||c.example^") {
		t.Fatalf("unexpected c at depth=1: %q", s)
	}
}

func TestResolveIncludeTarget(t *testing.T) {
	t.Parallel()
	got, err := resolveIncludeTarget("https://example.com/dir/list.txt", "more.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/dir/more.txt" {
		t.Fatalf("got=%q", got)
	}

	dir := t.TempDir()
	base := filepath.Join(dir, "list.txt")
	got, err = resolveIncludeTarget(base, "more.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(dir, "more.txt") {
		t.Fatalf("got=%q", got)
	}

	if _, err := resolveIncludeTarget(base, ""); err == nil {
		t.Fatalf("expected error for empty include")
	}
}

func TestRun_GeneratesRulesetsFromMixedInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mainList := filepath.Join(dir, "list.txt")
	extra := filepath.Join(dir, "extra.txt")

	if err := os.WriteFile(extra, []byte("||ads6.example.com^/banner.js$match-case\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		"!#include extra.txt",
		"0.0.0.0 ads1.example.com ads2.example.com",
		"ads3.example.com",
		"||ads4.example.com^",
		"||ads5.example.com^$important",
		"@@||allowme.example.com^$domain=site.example",
	}, "\n") + "\n"
	if err := os.WriteFile(mainList, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	outBlocks := filepath.Join(dir, "rules.json")
	outExceptions := filepath.Join(dir, "rules.exceptions.json")
	outAllow := filepath.Join(dir, "rules.allowlist.json")

	opts := options{
		OutBlocksPath:     outBlocks,
		OutExceptionsPath: outExceptions,
		OutAllowlistPath:  outAllow,
		MaxRules:          3,
		BlocksShards:      2,
		Sources:           []source{{Name: "local", URL: mainList}},
		FollowIncludes:    true,
		MaxIncludeDepth:   2,
		MaxIncludes:       10,
		Exceptions:        "all",
		AllowDomains:      []string{"support.example.com"},
		Timeout:           5 * time.Second,
		IncludeMainFrame:  false,
	}

	if err := run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	// Blocks shards exist and decode.
	paths, err := shardPaths(outBlocks, 2)
	if err != nil {
		t.Fatal(err)
	}
	var allBlocks []rule
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var shard []rule
		if err := json.Unmarshal(b, &shard); err != nil {
			t.Fatal(err)
		}
		// IDs restart per ruleset file.
		for i, r := range shard {
			if r.ID != i+1 {
				t.Fatalf("file=%s id=%d want %d", p, r.ID, i+1)
			}
			if r.Action.Type != "block" {
				t.Fatalf("file=%s action=%q", p, r.Action.Type)
			}
		}
		allBlocks = append(allBlocks, shard...)
	}
	if len(allBlocks) == 0 {
		t.Fatalf("expected blocks")
	}

	// Exceptions file exists and is allow rules.
	{
		b, err := os.ReadFile(outExceptions)
		if err != nil {
			t.Fatal(err)
		}
		var exc []rule
		if err := json.Unmarshal(b, &exc); err != nil {
			t.Fatal(err)
		}
		if len(exc) == 0 {
			t.Fatalf("expected exceptions")
		}
		if exc[0].Action.Type != "allow" || exc[0].Priority != 3 {
			t.Fatalf("exception=%+v", exc[0])
		}
	}

	// Allowlist rules exist and are highest-priority static allows.
	{
		b, err := os.ReadFile(outAllow)
		if err != nil {
			t.Fatal(err)
		}
		var allow []rule
		if err := json.Unmarshal(b, &allow); err != nil {
			t.Fatal(err)
		}
		if len(allow) != 1 {
			t.Fatalf("allowlist=%d", len(allow))
		}
		if allow[0].Action.Type != "allow" || allow[0].Priority != 4 {
			t.Fatalf("allow=%+v", allow[0])
		}
		if strings.Join(allow[0].Condition.RequestDomains, ",") != "support.example.com" {
			t.Fatalf("domains=%v", allow[0].Condition.RequestDomains)
		}
	}

	// Spot-check that important+match-case modifiers are reflected in output.
	foundImportant := false
	foundMatchCase := false
	for _, r := range allBlocks {
		if r.Priority == 2 {
			foundImportant = true
		}
		if r.Condition.IsURLFilterCaseSensitive != nil && *r.Condition.IsURLFilterCaseSensitive {
			foundMatchCase = true
		}
	}
	if !foundImportant {
		t.Fatalf("expected an important block rule")
	}
	if !foundMatchCase {
		t.Fatalf("expected a match-case rule")
	}
}
