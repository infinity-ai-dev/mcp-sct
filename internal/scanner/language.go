package scanner

import (
	"path/filepath"
	"strings"
)

var extensionMap = map[string]string{
	".py":    "python",
	".pyw":   "python",
	".js":    "javascript",
	".jsx":   "javascript",
	".ts":    "typescript",
	".tsx":   "typescript",
	".go":    "go",
	".java":  "java",
	".rb":    "ruby",
	".php":   "php",
	".cs":    "csharp",
	".c":     "c",
	".cpp":   "cpp",
	".h":     "c",
	".hpp":   "cpp",
	".rs":    "rust",
	".swift": "swift",
	".kt":    "kotlin",
	".scala": "scala",
	".sh":    "shell",
	".bash":  "shell",
	".zsh":   "shell",
	".sql":   "sql",
	".yaml":  "yaml",
	".yml":   "yaml",
	".json":  "json",
	".xml":   "xml",
	".html":  "html",
	".htm":   "html",
	".css":   "css",
}

// DetectLanguage determines the programming language from file extension.
func DetectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	if lang, ok := extensionMap[ext]; ok {
		return lang
	}
	return ""
}

// IsSourceFile returns true if the file is a known source code file.
func IsSourceFile(filePath string) bool {
	return DetectLanguage(filePath) != ""
}
