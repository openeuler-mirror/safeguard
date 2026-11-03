package audit

import "context"

// AppOption customizes runtime integration without changing configuration parsing.
type AppOption func(*runOptions)

// WithReadyNotification installs a one-shot notification after module startup.
// A failed notification cancels the run; a blocked notification is subject to the shutdown budget.
func WithReadyNotification(notify func(context.Context) error) AppOption {
	return func(options *runOptions) { options.ready = notify }
}
