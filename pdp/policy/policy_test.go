package policy

import (
	"log/slog"
	"strings"
	"testing"
)

func TestLoadFile(t *testing.T) {
	p, err := LoadFile("testdata/valid.yaml", slog.Default())
	if err != nil {
		t.Fatalf("expected valid policy to load, got error: %v", err)
	}
	if len(p.Rules) != 4 {
		t.Errorf("expected 4 rules, got %d", len(p.Rules))
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *Policy
		wantErr string
	}{
		{
			name: "valid policy",
			policy: &Policy{
				Version: 1,
				Rules:   []Rule{{ID: "r1", Allow: "true"}},
			},
		},
		{
			name:    "wrong version",
			policy:  &Policy{Version: 2, Rules: []Rule{{ID: "r1", Allow: "true"}}},
			wantErr: "unsupported policy version",
		},
		{
			name:    "missing version",
			policy:  &Policy{Version: 0, Rules: []Rule{{ID: "r1", Allow: "true"}}},
			wantErr: "unsupported policy version",
		},
		{
			name:    "empty rules",
			policy:  &Policy{Version: 1, Rules: []Rule{}},
			wantErr: "at least one rule",
		},
		{
			name:    "rule with empty id",
			policy:  &Policy{Version: 1, Rules: []Rule{{ID: "", Allow: "true"}}},
			wantErr: "id must not be empty",
		},
		{
			name: "duplicate rule ids",
			policy: &Policy{Version: 1, Rules: []Rule{
				{ID: "r1", Allow: "true"},
				{ID: "r1", Deny: "false"},
			}},
			wantErr: "duplicate id",
		},
		{
			name:    "rule with both allow and deny",
			policy:  &Policy{Version: 1, Rules: []Rule{{ID: "r1", Allow: "true", Deny: "false"}}},
			wantErr: "not both",
		},
		{
			name:    "rule with neither allow nor deny",
			policy:  &Policy{Version: 1, Rules: []Rule{{ID: "r1"}}},
			wantErr: "must have exactly one of allow or deny",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.policy)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("expected error containing %q, got nil", tc.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestRuleDecision(t *testing.T) {
	allow := Rule{ID: "r", Allow: "actor != null"}
	if d, e := allow.Decision(); d != "allow" || e != "actor != null" {
		t.Errorf("allow rule: got decision=%q expr=%q", d, e)
	}

	deny := Rule{ID: "r", Deny: "actor == null"}
	if d, e := deny.Decision(); d != "deny" || e != "actor == null" {
		t.Errorf("deny rule: got decision=%q expr=%q", d, e)
	}
}
