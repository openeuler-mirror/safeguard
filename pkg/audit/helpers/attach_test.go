package helpers

import (
	"errors"
	"reflect"
	"testing"
)

type fakeLink struct {
	name     string
	released *[]string
	err      error
}

func (l fakeLink) Destroy() error { *l.released = append(*l.released, l.name); return l.err }

func TestAttachRollbackContinuesAfterCleanupFailure(t *testing.T) {
	var released []string
	cause := errors.New("hook unavailable")
	err := AttachAll([]string{"one", "two", "three"}, func(name string) (Link, error) {
		if name == "three" {
			return nil, cause
		}
		return fakeLink{name, &released, errors.New("cleanup diagnostic")}, nil
	})
	if !errors.Is(err, cause) || !reflect.DeepEqual(released, []string{"two", "one"}) {
		t.Fatalf("err=%v released=%v", err, released)
	}
}

func TestAttachSuccessKeepsModuleOwnership(t *testing.T) {
	var released []string
	err := AttachAll([]string{"one"}, func(name string) (Link, error) { return fakeLink{name, &released, nil}, nil })
	if err != nil || len(released) != 0 {
		t.Fatalf("err=%v released=%v", err, released)
	}
}
