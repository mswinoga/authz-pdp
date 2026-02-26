package policy

import (
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

const supportedVersion = 1

// Policy is the top-level structure of a PDP policy file.
type Policy struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Rule is a single named authorization rule.
// Exactly one of Allow or Deny must be set.
type Rule struct {
	ID    string `yaml:"id"`
	Allow string `yaml:"allow,omitempty"`
	Deny  string `yaml:"deny,omitempty"`
}

// Decision returns "allow" or "deny" and the CEL expression for this rule.
// Panics if the rule is not valid; call Validate first.
func (r Rule) Decision() (decision, expr string) {
	if r.Allow != "" {
		return "allow", r.Allow
	}
	return "deny", r.Deny
}

// LoadFile reads and validates a policy from a YAML file.
func LoadFile(path string, logger *slog.Logger) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}
	if err := Validate(&p); err != nil {
		logger.Error("policy validation failed", "path", path, "error", err)
		return nil, err
	}
	logger.Info("policy loaded", "path", path, "version", p.Version, "rules", len(p.Rules))
	return &p, nil
}

// Validate checks the policy against all schema constraints.
func Validate(p *Policy) error {
	if p.Version != supportedVersion {
		return fmt.Errorf("unsupported policy version %d (expected %d)", p.Version, supportedVersion)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy must contain at least one rule")
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for i, r := range p.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule[%d]: id must not be empty", i)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("rule[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = struct{}{}

		hasAllow := r.Allow != ""
		hasDeny := r.Deny != ""
		if hasAllow && hasDeny {
			return fmt.Errorf("rule %q: must have exactly one of allow or deny, not both", r.ID)
		}
		if !hasAllow && !hasDeny {
			return fmt.Errorf("rule %q: must have exactly one of allow or deny", r.ID)
		}
	}
	return nil
}
