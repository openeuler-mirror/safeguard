package helpers

import "fmt"

// StageError identifies the module and operation while preserving the cause.
type StageError struct {
	Module, Stage string
	Err           error
}

func (e *StageError) Error() string { return fmt.Sprintf("%s %s: %v", e.Module, e.Stage, e.Err) }
func (e *StageError) Unwrap() error { return e.Err }
func During(module, stage string, err error) error {
	if err == nil {
		return nil
	}
	return &StageError{Module: module, Stage: stage, Err: err}
}
