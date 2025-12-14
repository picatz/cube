package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseABPLine_BasicBlock(t *testing.T) {
	r, ok, unsupported := parseABPLine("||doubleclick.net^")
	if !ok || unsupported {
		t.Fatalf("ok=%v unsupported=%v", ok, unsupported)
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
	r, ok, unsupported := parseABPLine("@@||example.com^")
	if !ok || unsupported {
		t.Fatalf("ok=%v unsupported=%v", ok, unsupported)
	}
	if !r.Exception {
		t.Fatalf("expected exception")
	}
	if r.Host != "example.com" {
		t.Fatalf("host=%q", r.Host)
	}
}

func TestParseABPLine_OptionsThirdPartyAndTypes(t *testing.T) {
	r, ok, unsupported := parseABPLine("||example.com^$third-party,script,xmlhttprequest")
	if !ok || unsupported {
		t.Fatalf("ok=%v unsupported=%v", ok, unsupported)
	}
	if r.Options.DomainType != "thirdParty" {
		t.Fatalf("domainType=%q", r.Options.DomainType)
	}
	if strings.Join(r.Options.ResourceTypes, ",") != "script,xmlhttprequest" {
		t.Fatalf("resourceTypes=%v", r.Options.ResourceTypes)
	}
}

func TestParseABPLine_DomainOptionToInitiatorDomains(t *testing.T) {
	r, ok, unsupported := parseABPLine("||tracker.example^$domain=foo.com|~bar.com,script")
	if !ok || unsupported {
		t.Fatalf("ok=%v unsupported=%v", ok, unsupported)
	}
	if strings.Join(r.Options.InitiatorDomains, ",") != "foo.com" {
		t.Fatalf("initiatorDomains=%v", r.Options.InitiatorDomains)
	}
	if strings.Join(r.Options.ExcludedInitiatorDomains, ",") != "bar.com" {
		t.Fatalf("excludedInitiatorDomains=%v", r.Options.ExcludedInitiatorDomains)
	}
}

func TestParseABPLine_UnsupportedOptionSkips(t *testing.T) {
	_, ok, unsupported := parseABPLine("||example.com^$redirect=noopjs")
	if !ok || !unsupported {
		t.Fatalf("ok=%v unsupported=%v", ok, unsupported)
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
	host, path, ok := parseABPPattern("||example.com^/ads.js")
	if !ok {
		t.Fatalf("expected ok")
	}
	if host != "example.com" {
		t.Fatalf("host=%q", host)
	}
	if path != "/ads.js" {
		t.Fatalf("path=%q", path)
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
