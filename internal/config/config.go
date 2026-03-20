package config

import (
	"encoding/json"
	"os"
	"runtime"
)

type Config struct {
	// Server settings
	Mode      string `json:"mode"`      // "self-hosted" or "cloud"
	Transport string `json:"transport"` // "stdio" or "http"
	Address   string `json:"address,omitempty"`

	// Scanner settings
	Workers           int      `json:"workers"`
	MaxFileSize       int64    `json:"max_file_size"`
	ExcludePatterns   []string `json:"exclude_patterns"`
	SeverityThreshold string   `json:"severity_threshold"`

	// Rules settings
	BuiltinRulesEnabled bool     `json:"builtin_rules_enabled"`
	CustomRulesDirs     []string `json:"custom_rules_dirs"`

	// AI Bridge settings
	AIBridgeEnabled bool   `json:"ai_bridge_enabled"`
	AIBridgePort    int    `json:"ai_bridge_port"`
	PythonPath      string `json:"python_path"`
	AIScriptPath    string `json:"ai_script_path"`

	// Logging
	LogLevel string `json:"log_level"`
}

func DefaultConfig() *Config {
	return &Config{
		Mode:                "self-hosted",
		Transport:           "stdio",
		Workers:             runtime.NumCPU(),
		MaxFileSize:         1 * 1024 * 1024,
		ExcludePatterns:     defaultExcludePatterns(),
		SeverityThreshold:   "LOW",
		BuiltinRulesEnabled: true,
		CustomRulesDirs:     []string{"rules/custom"},
		AIBridgeEnabled:     false,
		AIBridgePort:        9817,
		PythonPath:          "python3",
		LogLevel:            "info",
	}
}

func defaultExcludePatterns() []string {
	return []string{
		"node_modules/**",
		"vendor/**",
		".git/**",
		"*.min.js",
		"*.min.css",
		"*.lock",
		"go.sum",
		"package-lock.json",
		"*.pb.go",
		"*_generated.*",
		"dist/**",
		"build/**",
		".venv/**",
		"__pycache__/**",
	}
}

func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
