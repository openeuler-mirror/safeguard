package helpers

import (
	"context"
	"errors"
	"testing"
)

func TestCancelBetweenStartupStages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := StartStage(ctx, "mount", "configure", func() error { cancel(); return nil }); err != nil {
		t.Fatal(err)
	}
	called := false
	err := StartStage(ctx, "mount", "attach", func() error { called = true; return nil })
	var stage *StageError
	if called || !errors.Is(err, context.Canceled) || !errors.As(err, &stage) || stage.Stage != "attach" {
		t.Fatalf("called=%v err=%v", called, err)
	}
	ready := false
	ReportReady(WithReadiness(ctx, func() { ready = true }))
	if ready {
		t.Fatal("reported readiness after cancellation")
	}
}
