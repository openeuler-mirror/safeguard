package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type auditErrors []error

func (e auditErrors) Error() string {
	messages := make([]string, len(e))
	for i, err := range e {
		messages[i] = err.Error()
	}
	sort.Strings(messages)
	return strings.Join(messages, "; ")
}

func (e auditErrors) Is(target error) bool {
	for _, err := range e {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func (e auditErrors) As(target interface{}) bool {
	for _, err := range e {
		if errors.As(err, target) {
			return true
		}
	}
	return false
}

func joinFailure(previous, next error) error {
	if previous == nil {
		return next
	}
	if next == nil {
		return previous
	}
	if list, ok := previous.(auditErrors); ok {
		return append(list, next)
	}
	return auditErrors{previous, next}
}

func parentFailure(ctx context.Context, previous error) error {
	err := ctx.Err()
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(previous, err) {
		return joinFailure(previous, fmt.Errorf("audit parent context: %w", err))
	}
	return previous
}
