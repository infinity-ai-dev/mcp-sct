package rules

import (
	"fmt"
	"sync"
)

// Registry holds all loaded rules, indexed for fast lookup.
type Registry struct {
	mu         sync.RWMutex
	rules      map[string]*Rule
	byLanguage map[string][]*Rule
	byCategory map[string][]*Rule
}

func NewRegistry() *Registry {
	return &Registry{
		rules:      make(map[string]*Rule),
		byLanguage: make(map[string][]*Rule),
		byCategory: make(map[string][]*Rule),
	}
}

// Register adds a rule to the registry.
func (reg *Registry) Register(r *Rule) error {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	if !r.IsEnabled() {
		return nil
	}

	if _, exists := reg.rules[r.ID]; exists {
		return fmt.Errorf("duplicate rule id: %s", r.ID)
	}

	reg.rules[r.ID] = r

	for _, lang := range r.Languages {
		reg.byLanguage[lang] = append(reg.byLanguage[lang], r)
	}
	reg.byCategory[r.Category] = append(reg.byCategory[r.Category], r)

	return nil
}

// RegisterAll adds multiple rules, skipping duplicates (last one wins).
func (reg *Registry) RegisterAll(rules []*Rule) error {
	for _, r := range rules {
		if existing, exists := reg.rules[r.ID]; exists {
			// remove old one from indexes
			reg.remove(existing)
		}
		if err := reg.Register(r); err != nil {
			return err
		}
	}
	return nil
}

func (reg *Registry) remove(r *Rule) {
	delete(reg.rules, r.ID)
	for _, lang := range r.Languages {
		filtered := filterOut(reg.byLanguage[lang], r.ID)
		reg.byLanguage[lang] = filtered
	}
	filtered := filterOut(reg.byCategory[r.Category], r.ID)
	reg.byCategory[r.Category] = filtered
}

func filterOut(rules []*Rule, id string) []*Rule {
	result := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		if r.ID != id {
			result = append(result, r)
		}
	}
	return result
}

// ForLanguage returns all rules applicable to a language.
func (reg *Registry) ForLanguage(lang string) []*Rule {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.byLanguage[lang]
}

// ForCategory returns all rules in a category.
func (reg *Registry) ForCategory(cat string) []*Rule {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.byCategory[cat]
}

// Get returns a rule by ID.
func (reg *Registry) Get(id string) (*Rule, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	r, ok := reg.rules[id]
	return r, ok
}

// All returns all registered rules.
func (reg *Registry) All() []*Rule {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	result := make([]*Rule, 0, len(reg.rules))
	for _, r := range reg.rules {
		result = append(result, r)
	}
	return result
}

// Count returns the total number of registered rules.
func (reg *Registry) Count() int {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return len(reg.rules)
}
