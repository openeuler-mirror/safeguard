package processcheck

import "strings"

type Matcher struct {
	allow map[string]struct{}
}

func NewMatcher(values []string) Matcher {
	allow := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		allow[trimmed] = struct{}{}
	}
	return Matcher{allow: allow}
}

func (m Matcher) Allowed(command, parent string) bool {
	if len(m.allow) == 0 {
		return true
	}
	if _, ok := m.allow[command]; ok {
		return true
	}
	if _, ok := m.allow[parent]; ok {
		return true
	}
	return false
}
