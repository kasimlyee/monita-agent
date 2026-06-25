// Package redact applies configurable regex redaction to log line content.
// It is called before any log entry touches the local buffer so secrets never
// reach disk on either side (SPEC.md §7).
package redact

import (
	"fmt"
	"regexp"
	"strings"
)

// defaultPatterns covers the most common secret shapes that appear in logs.
var defaultPatterns = []string{
	// AWS access key IDs
	`AKIA[0-9A-Z]{16}`,
	// Generic API key assignments (api_key = "...", apiKey: "...")
	`(?i)api[_-]?key["'\s:=]+[a-zA-Z0-9\-_]{20,}`,
	// Bearer tokens in Authorization headers or URLs
	`(?i)bearer\s+[a-zA-Z0-9._\-]{20,}`,
	// Generic secret/password/token assignments
	`(?i)(secret|password|passwd|pwd|token)["'\s:=]+[^\s"']{8,}`,
	// Common env-var patterns written into logs (SECRET=value)
	`(?i)(SECRET|PASSWORD|TOKEN|API_KEY)=[^\s&"']{6,}`,
}

const redacted = "[REDACTED]"

// Redactor holds compiled patterns and applies them in order.
type Redactor struct {
	patterns []*regexp.Regexp
}

// New compiles the default pattern set plus any user-supplied additions.
// Returns an error if any pattern fails to compile.
func New(userPatterns []string) (*Redactor, error) {
	all := append(defaultPatterns, userPatterns...)
	compiled := make([]*regexp.Regexp, 0, len(all))
	for _, p := range all {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("redact pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	return &Redactor{patterns: compiled}, nil
}

// Redact returns a copy of line with all matching secret patterns replaced.
// It operates on the full matched substring so partial replacement never
// leaks a prefix of a secret.
func (r *Redactor) Redact(line string) string {
	for _, re := range r.patterns {
		line = re.ReplaceAllStringFunc(line, func(match string) string {
			// For key=value patterns, preserve the key name so logs remain
			// interpretable; replace only the value portion.
			for _, sep := range []string{"=", ":", " "} {
				if idx := strings.Index(match, sep); idx >= 0 {
					return match[:idx+len(sep)] + redacted
				}
			}
			return redacted
		})
	}
	return line
}