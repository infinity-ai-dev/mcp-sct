package rules

import (
	"fmt"
	"regexp"
)

// Rule represents a single security detection rule loaded from YAML.
type Rule struct {
	ID        string   `yaml:"id"`
	Version   string   `yaml:"version"`
	Enabled   *bool    `yaml:"enabled"` // pointer to distinguish unset from false
	Languages []string `yaml:"languages"`
	Severity  string   `yaml:"severity"`
	Category  string   `yaml:"category"`
	CWE       string   `yaml:"cwe"`
	OWASP     string   `yaml:"owasp"`

	Patterns        []Pattern `yaml:"patterns"`
	ExcludePatterns []Pattern `yaml:"exclude_patterns"`

	Message     string   `yaml:"message"`
	FixTemplate string   `yaml:"fix_template"`
	References  []string `yaml:"references"`
	Confidence  float64  `yaml:"confidence"`

	Metadata RuleMetadata `yaml:"metadata"`

	// Compiled regexes (populated after loading)
	compiledPatterns        []*regexp.Regexp
	compiledExcludePatterns []*regexp.Regexp
}

type Pattern struct {
	Pattern string `yaml:"pattern"`
	Type    string `yaml:"type"` // "regex" (default), "token", "ast"
	Flags   []string `yaml:"flags"`
}

type RuleMetadata struct {
	Author string   `yaml:"author"`
	Tags   []string `yaml:"tags"`
}

func (r *Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// Compile pre-compiles all regex patterns for performance.
func (r *Rule) Compile() error {
	r.compiledPatterns = make([]*regexp.Regexp, 0, len(r.Patterns))
	for _, p := range r.Patterns {
		if p.Type != "" && p.Type != "regex" {
			continue // skip non-regex patterns for now
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return fmt.Errorf("rule %s: invalid regex %q: %w", r.ID, p.Pattern, err)
		}
		r.compiledPatterns = append(r.compiledPatterns, re)
	}

	r.compiledExcludePatterns = make([]*regexp.Regexp, 0, len(r.ExcludePatterns))
	for _, p := range r.ExcludePatterns {
		if p.Type != "" && p.Type != "regex" {
			continue
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return fmt.Errorf("rule %s: invalid exclude regex %q: %w", r.ID, p.Pattern, err)
		}
		r.compiledExcludePatterns = append(r.compiledExcludePatterns, re)
	}

	if r.Confidence == 0 {
		r.Confidence = 0.7 // default confidence
	}

	return nil
}

func (r *Rule) CompiledPatterns() []*regexp.Regexp {
	return r.compiledPatterns
}

func (r *Rule) CompiledExcludePatterns() []*regexp.Regexp {
	return r.compiledExcludePatterns
}
