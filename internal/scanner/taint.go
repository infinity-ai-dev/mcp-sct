package scanner

import (
	"regexp"
	"strings"

	"github.com/mcp-sct/mcp-sct/internal/types"
)

// TaintEngine performs source-to-sink data flow analysis within a single file.
// It tracks variables that receive user input (sources) and detects when they
// flow into dangerous functions (sinks) without sanitization.
type TaintEngine struct {
	sources    []TaintSource
	sinks      []TaintSink
	sanitizers []TaintSanitizer
}

// TaintSource defines where user-controlled data enters the code.
type TaintSource struct {
	Language string
	Pattern  *regexp.Regexp
	Label    string // e.g., "request.body", "sys.argv"
}

// TaintSink defines dangerous functions that should not receive tainted data.
type TaintSink struct {
	Language        string
	Pattern         *regexp.Regexp
	VulnType        string // e.g., "injection", "xss"
	CWE             string
	OWASP           string
	Message         string
	Severity        string
	ArgPositions    []int // which argument positions are dangerous (0-indexed, -1 = any)
}

// TaintSanitizer defines functions that clean tainted data.
type TaintSanitizer struct {
	Language string
	Pattern  *regexp.Regexp
}

// NewTaintEngine creates a taint engine with predefined source/sink definitions.
func NewTaintEngine() *TaintEngine {
	e := &TaintEngine{}
	e.registerPython()
	e.registerJavaScript()
	e.registerGo()
	return e
}

func (e *TaintEngine) registerPython() {
	lang := "python"

	// Sources: where user input enters
	e.sources = append(e.sources,
		TaintSource{lang, regexp.MustCompile(`request\.(args|form|data|json|values|files|cookies|headers)\b`), "request"},
		TaintSource{lang, regexp.MustCompile(`request\.GET|request\.POST|request\.body`), "django.request"},
		TaintSource{lang, regexp.MustCompile(`input\s*\(`), "input()"},
		TaintSource{lang, regexp.MustCompile(`sys\.argv`), "sys.argv"},
		TaintSource{lang, regexp.MustCompile(`os\.environ\.get\(|os\.getenv\(`), "env"},
	)

	// Sinks: dangerous functions
	e.sinks = append(e.sinks,
		TaintSink{lang, regexp.MustCompile(`cursor\.execute\(`), "injection", "CWE-89", "A03:2021",
			"Tainted data flows to SQL query without parameterization", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`os\.system\(`), "injection", "CWE-78", "A03:2021",
			"Tainted data flows to OS command execution", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`subprocess\.(call|run|Popen)\(`), "injection", "CWE-78", "A03:2021",
			"Tainted data flows to subprocess execution", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`eval\(`), "injection", "CWE-95", "A03:2021",
			"Tainted data flows to eval()", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`exec\(`), "injection", "CWE-95", "A03:2021",
			"Tainted data flows to exec()", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`render_template_string\(`), "xss", "CWE-79", "A03:2021",
			"Tainted data flows to template rendering without escaping", "HIGH", []int{0}},
		TaintSink{lang, regexp.MustCompile(`Markup\(`), "xss", "CWE-79", "A03:2021",
			"Tainted data flows to Markup() bypassing auto-escape", "HIGH", []int{0}},
		TaintSink{lang, regexp.MustCompile(`open\(`), "path-traversal", "CWE-22", "A01:2021",
			"Tainted data flows to file open without path validation", "HIGH", []int{0}},
		TaintSink{lang, regexp.MustCompile(`pickle\.loads\(`), "deserialization", "CWE-502", "A08:2021",
			"Tainted data flows to insecure deserialization", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`yaml\.load\(`), "deserialization", "CWE-502", "A08:2021",
			"Tainted data flows to unsafe YAML load", "HIGH", []int{0}},
	)

	// Sanitizers: functions that clean data
	e.sanitizers = append(e.sanitizers,
		TaintSanitizer{lang, regexp.MustCompile(`escape\(|html\.escape\(|bleach\.clean\(|sanitize\(|quote\(`)},
		TaintSanitizer{lang, regexp.MustCompile(`int\(|float\(|bool\(`)},
		TaintSanitizer{lang, regexp.MustCompile(`re\.match\(|re\.fullmatch\(`)},
		TaintSanitizer{lang, regexp.MustCompile(`filepath\.Clean|os\.path\.abspath|os\.path\.realpath`)},
		TaintSanitizer{lang, regexp.MustCompile(`shlex\.quote\(|shlex\.split\(`)},
	)
}

func (e *TaintEngine) registerJavaScript() {
	lang := "javascript"

	e.sources = append(e.sources,
		TaintSource{lang, regexp.MustCompile(`req\.(body|query|params|headers|cookies)\b`), "req"},
		TaintSource{lang, regexp.MustCompile(`request\.(body|query|params)\b`), "request"},
		TaintSource{lang, regexp.MustCompile(`document\.(location|URL|referrer|cookie)`), "document"},
		TaintSource{lang, regexp.MustCompile(`window\.location`), "location"},
		TaintSource{lang, regexp.MustCompile(`process\.argv`), "process.argv"},
	)

	e.sinks = append(e.sinks,
		TaintSink{lang, regexp.MustCompile(`\.query\(`), "injection", "CWE-89", "A03:2021",
			"Tainted data flows to database query", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`exec\(`), "injection", "CWE-78", "A03:2021",
			"Tainted data flows to command execution", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`execSync\(`), "injection", "CWE-78", "A03:2021",
			"Tainted data flows to synchronous command execution", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`eval\(`), "injection", "CWE-95", "A03:2021",
			"Tainted data flows to eval()", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`\.innerHTML\s*=`), "xss", "CWE-79", "A03:2021",
			"Tainted data flows to innerHTML assignment", "HIGH", []int{-1}},
		TaintSink{lang, regexp.MustCompile(`document\.write\(`), "xss", "CWE-79", "A03:2021",
			"Tainted data flows to document.write()", "HIGH", []int{0}},
		TaintSink{lang, regexp.MustCompile(`fs\.(readFile|readFileSync|writeFile|writeFileSync)\(`), "path-traversal", "CWE-22", "A01:2021",
			"Tainted data flows to file system operation", "HIGH", []int{0}},
		TaintSink{lang, regexp.MustCompile(`res\.(send|json|render)\(`), "xss", "CWE-79", "A03:2021",
			"Tainted data flows directly to response without sanitization", "MEDIUM", []int{0}},
	)

	e.sanitizers = append(e.sanitizers,
		TaintSanitizer{lang, regexp.MustCompile(`escape\(|sanitize\(|DOMPurify\.sanitize\(|encodeURIComponent\(`)},
		TaintSanitizer{lang, regexp.MustCompile(`parseInt\(|parseFloat\(|Number\(`)},
		TaintSanitizer{lang, regexp.MustCompile(`validator\.|joi\.|zod\.`)},
		TaintSanitizer{lang, regexp.MustCompile(`path\.normalize\(|path\.resolve\(`)},
	)
}

func (e *TaintEngine) registerGo() {
	lang := "go"

	e.sources = append(e.sources,
		TaintSource{lang, regexp.MustCompile(`r\.(FormValue|URL\.Query|PostFormValue|Body|Header\.Get)\(`), "http.Request"},
		TaintSource{lang, regexp.MustCompile(`c\.(Param|Query|PostForm|FormFile)\(`), "gin.Context"},
		TaintSource{lang, regexp.MustCompile(`os\.Args`), "os.Args"},
	)

	e.sinks = append(e.sinks,
		TaintSink{lang, regexp.MustCompile(`db\.(Query|Exec|QueryRow)\(`), "injection", "CWE-89", "A03:2021",
			"Tainted data flows to database query", "CRITICAL", []int{0}},
		TaintSink{lang, regexp.MustCompile(`exec\.Command\(`), "injection", "CWE-78", "A03:2021",
			"Tainted data flows to command execution", "CRITICAL", []int{-1}},
		TaintSink{lang, regexp.MustCompile(`os\.Open\(|os\.ReadFile\(`), "path-traversal", "CWE-22", "A01:2021",
			"Tainted data flows to file operation", "HIGH", []int{0}},
		TaintSink{lang, regexp.MustCompile(`template\.HTML\(`), "xss", "CWE-79", "A03:2021",
			"Tainted data cast to template.HTML bypassing escaping", "HIGH", []int{0}},
		TaintSink{lang, regexp.MustCompile(`fmt\.Fprintf\(w,`), "xss", "CWE-79", "A03:2021",
			"Tainted data written directly to HTTP response", "MEDIUM", []int{-1}},
	)

	e.sanitizers = append(e.sanitizers,
		TaintSanitizer{lang, regexp.MustCompile(`html\.EscapeString\(|template\.HTMLEscapeString\(`)},
		TaintSanitizer{lang, regexp.MustCompile(`strconv\.(Atoi|ParseInt|ParseFloat)\(`)},
		TaintSanitizer{lang, regexp.MustCompile(`filepath\.(Clean|Abs)\(`)},
		TaintSanitizer{lang, regexp.MustCompile(`regexp\.MustCompile.*\.MatchString\(`)},
	)
}

// taintedVar tracks a variable that holds user-controlled data.
type taintedVar struct {
	name       string
	sourceLine int
	sourceLabel string
}

// Analyze performs taint analysis on file content and returns findings.
func (e *TaintEngine) Analyze(filePath, content, language string) []types.Finding {
	if language == "typescript" {
		language = "javascript" // same rules
	}

	lines := strings.Split(content, "\n")
	tainted := make(map[string]*taintedVar) // variable name -> taint info
	var findings []types.Finding

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if isComment(trimmed, language) {
			continue
		}

		// 1. Check if this line introduces a tainted variable (source)
		for _, src := range e.sources {
			if src.Language != language {
				continue
			}
			if src.Pattern.MatchString(line) {
				// Extract variable being assigned
				varName := extractAssignedVar(line, language)
				if varName != "" {
					tainted[varName] = &taintedVar{
						name:       varName,
						sourceLine: lineNum + 1,
						sourceLabel: src.Label,
					}
				}
			}
		}

		// 2. Track taint propagation through assignments
		assignedVar, assignedFrom := extractAssignment(line, language)
		if assignedVar != "" && assignedFrom != "" {
			// Check if the RHS contains any tainted variable
			for taintName := range tainted {
				if strings.Contains(assignedFrom, taintName) {
					// Check if sanitized
					if !e.isSanitized(line, language) {
						tainted[assignedVar] = &taintedVar{
							name:        assignedVar,
							sourceLine:  tainted[taintName].sourceLine,
							sourceLabel: tainted[taintName].sourceLabel,
						}
					}
					break
				}
			}
		}

		// 3. Check if tainted data flows to a sink
		for _, sink := range e.sinks {
			if sink.Language != language {
				continue
			}
			if !sink.Pattern.MatchString(line) {
				continue
			}

			// Check if any tainted variable appears in the sink line
			for taintName, taintInfo := range tainted {
				if !strings.Contains(line, taintName) {
					continue
				}
				// Verify it's not sanitized on this line
				if e.isSanitized(line, language) {
					continue
				}

				snippet := extractSnippetRange(lines, lineNum+1, 2)
				findings = append(findings, types.Finding{
					RuleID:   "taint-" + sink.VulnType,
					Severity: types.ParseSeverity(sink.Severity),
					Category: sink.VulnType,
					Message: sink.Message +
						". Variable '" + taintName + "' is tainted from " +
						taintInfo.sourceLabel + " (line " +
						itoa(taintInfo.sourceLine) + ").",
					FilePath:   filePath,
					StartLine:  lineNum + 1,
					EndLine:    lineNum + 1,
					Snippet:    snippet,
					CWE:        sink.CWE,
					OWASP:      sink.OWASP,
					Confidence: 0.70,
				})
				break // one finding per sink match
			}
		}
	}

	return findings
}

func (e *TaintEngine) isSanitized(line, language string) bool {
	for _, san := range e.sanitizers {
		if san.Language != language {
			continue
		}
		if san.Pattern.MatchString(line) {
			return true
		}
	}
	return false
}

func isComment(line, language string) bool {
	switch language {
	case "python":
		return strings.HasPrefix(line, "#")
	case "javascript", "go", "java":
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*")
	}
	return false
}

// extractAssignedVar gets the variable name from an assignment line.
func extractAssignedVar(line, language string) string {
	line = strings.TrimSpace(line)

	switch language {
	case "python":
		if idx := strings.Index(line, "="); idx > 0 {
			lhs := strings.TrimSpace(line[:idx])
			if lhs != "" && !strings.ContainsAny(lhs, "!<>=+- ") {
				return lhs
			}
		}
	case "javascript":
		// var/let/const x = ...
		for _, prefix := range []string{"const ", "let ", "var "} {
			if strings.HasPrefix(line, prefix) {
				rest := strings.TrimPrefix(line, prefix)
				if idx := strings.Index(rest, "="); idx > 0 {
					return strings.TrimSpace(rest[:idx])
				}
			}
		}
		// x = ...
		if idx := strings.Index(line, "="); idx > 0 && !strings.Contains(line[:idx], "(") {
			lhs := strings.TrimSpace(line[:idx])
			if lhs != "" && !strings.ContainsAny(lhs, "!<>=+- ") {
				return lhs
			}
		}
	case "go":
		// x := ... or x = ...
		if idx := strings.Index(line, ":="); idx > 0 {
			lhs := strings.TrimSpace(line[:idx])
			parts := strings.Split(lhs, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
		if idx := strings.Index(line, "="); idx > 0 && !strings.Contains(line[:idx], ":") {
			lhs := strings.TrimSpace(line[:idx])
			if lhs != "" && !strings.ContainsAny(lhs, "!<>=+- (") {
				return lhs
			}
		}
	}
	return ""
}

// extractAssignment returns (variable, rhs_expression) from an assignment.
func extractAssignment(line, language string) (string, string) {
	line = strings.TrimSpace(line)

	var eqIdx int
	switch language {
	case "go":
		if idx := strings.Index(line, ":="); idx > 0 {
			eqIdx = idx
			lhs := strings.TrimSpace(line[:eqIdx])
			rhs := strings.TrimSpace(line[eqIdx+2:])
			return lhs, rhs
		}
	}

	// General assignment
	eqIdx = strings.Index(line, "=")
	if eqIdx <= 0 {
		return "", ""
	}
	// Skip ==, !=, <=, >=
	if eqIdx > 0 && (line[eqIdx-1] == '!' || line[eqIdx-1] == '<' || line[eqIdx-1] == '>') {
		return "", ""
	}
	if eqIdx+1 < len(line) && line[eqIdx+1] == '=' {
		return "", ""
	}

	lhs := strings.TrimSpace(line[:eqIdx])
	rhs := strings.TrimSpace(line[eqIdx+1:])

	// Strip declaration keywords
	for _, kw := range []string{"const ", "let ", "var "} {
		lhs = strings.TrimPrefix(lhs, kw)
	}

	if lhs == "" || strings.ContainsAny(lhs, "({[") {
		return "", ""
	}

	return lhs, rhs
}

func extractSnippetRange(lines []string, targetLine, context int) string {
	start := targetLine - context - 1
	if start < 0 {
		start = 0
	}
	end := targetLine + context
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
