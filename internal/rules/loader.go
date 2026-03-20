package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFromFS loads all YAML rule files from an fs.FS (used for embedded rules).
func LoadFromFS(fsys fs.FS) ([]*Rule, error) {
	var rules []*Rule
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		r, err := parseRule(data, path)
		if err != nil {
			return err
		}
		rules = append(rules, r)
		return nil
	})
	return rules, err
}

// LoadFromDir loads all YAML rule files from a directory on disk.
func LoadFromDir(dir string) ([]*Rule, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	var rules []*Rule
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		r, err := parseRule(data, path)
		if err != nil {
			return err
		}
		rules = append(rules, r)
		return nil
	})
	return rules, err
}

func parseRule(data []byte, source string) (*Rule, error) {
	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", source, err)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("rule in %s has no id", source)
	}
	if len(r.Patterns) == 0 {
		return nil, fmt.Errorf("rule %s in %s has no patterns", r.ID, source)
	}
	if err := r.Compile(); err != nil {
		return nil, err
	}
	return &r, nil
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yml" || ext == ".yaml"
}
