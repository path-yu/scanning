package rules

import (
	"path/filepath"
	"testing"
)

func TestWildcard(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		fold    bool
		want    bool
	}{
		{"*.example.com", "api.example.com", true, true},
		{"*.example.com", "example.com", true, false},
		{"/api/*", "/api/users", false, true},
		{"/api/*", "/v1/users", false, false},
		{"application/*", "application/json", true, true},
		{"GET", "get", true, true},
		{"a?c", "abc", false, true},
	}
	for _, item := range cases {
		if got := wildcard(item.pattern, item.value, item.fold); got != item.want {
			t.Fatalf("wildcard(%q,%q)=%v want %v", item.pattern, item.value, got, item.want)
		}
	}
}

func TestMatchAndValidation(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.Save(Rule{
		Name:     "mock json",
		Enabled:  true,
		Priority: 10,
		Phase:    PhaseRequest,
		Match:    Match{Methods: []string{"GET", "POST"}, Host: "*.example.com", Path: "/api/*"},
		Actions:  []Action{{Type: ActionMock, Status: 201, Body: strPtr(`{"ok":true}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID == "" {
		t.Fatal("missing id")
	}

	matches := store.Match(PhaseRequest, Meta{Method: "get", Host: "API.EXAMPLE.COM", Path: "/api/v1"})
	if len(matches) != 1 || matches[0].ID != rule.ID {
		t.Fatalf("matches = %+v", matches)
	}
	if got := store.Match(PhaseRequest, Meta{Method: "DELETE", Host: "api.example.com", Path: "/api/v1"}); len(got) != 0 {
		t.Fatalf("unexpected matches: %+v", got)
	}
	if got := store.Match(PhaseResponse, Meta{Method: "GET", Host: "api.example.com", Path: "/api/v1"}); len(got) != 0 {
		t.Fatalf("phase should not match: %+v", got)
	}

	if _, err := store.Save(Rule{Name: "", Phase: PhaseRequest}); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := store.Save(Rule{Name: "bad", Phase: "other", Actions: []Action{{Type: ActionMock}}}); err == nil {
		t.Fatal("expected phase validation error")
	}
	if _, err := store.Save(Rule{Name: "bad", Phase: PhaseRequest, Actions: []Action{{Type: "unknown"}}}); err == nil {
		t.Fatal("expected action validation error")
	}
}

func TestResponseMatchingAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.Save(Rule{
		Name:    "500 rewrite",
		Enabled: true,
		Phase:   PhaseResponse,
		Match:   Match{Status: "5xx", Mime: "application/json", Host: "api.example.com"},
		Actions: []Action{{Type: ActionRewriteResponse, Status: 200, Body: strPtr("ok")}},
	})
	if err != nil {
		t.Fatal(err)
	}

	matches := store.Match(PhaseResponse, Meta{Status: 503, Mime: "application/json", Host: "api.example.com"})
	if len(matches) != 1 {
		t.Fatalf("matches=%+v", matches)
	}
	if got := store.Match(PhaseResponse, Meta{Status: 404, Mime: "application/json", Host: "api.example.com"}); len(got) != 0 {
		t.Fatalf("unexpected match: %+v", got)
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	list := reloaded.List()
	if len(list) != 1 || list[0].ID != rule.ID || list[0].Actions[0].Body == nil {
		t.Fatalf("reloaded = %+v", list)
	}
	if !reloaded.Delete(rule.ID) {
		t.Fatal("delete failed")
	}
	if _, err := NewStore(path); err != nil {
		t.Fatal(err)
	}
}

func strPtr(value string) *string { return &value }
