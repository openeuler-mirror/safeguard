package helpers

import (
	"errors"
	"fmt"
	"testing"
)

func TestStageErrorSurvivesCoordinatorWrapping(t *testing.T) {
	cause := errors.New("permission denied")
	for _, module := range []string{"fileaccess", "mount", "process", "network"} {
		for _, stage := range []string{"load", "configure", "attach", "buffer", "consume"} {
			err := fmt.Errorf("audit task: %w", During(module, stage, cause))
			var diagnostic *StageError
			if !errors.As(err, &diagnostic) || diagnostic.Module != module || diagnostic.Stage != stage || !errors.Is(err, cause) {
				t.Fatalf("%s/%s: %v", module, stage, err)
			}
		}
	}
	if During("network", "consume", nil) != nil {
		t.Fatal("success turned into error")
	}
}
