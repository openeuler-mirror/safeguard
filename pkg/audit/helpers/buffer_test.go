package helpers

import (
	"errors"
	"strings"
	"testing"
)

type fakeBuffer struct{ starts int }

func (b *fakeBuffer) Start() { b.starts++ }
func (b *fakeBuffer) Stop()  {}
func (b *fakeBuffer) Close() {}

func TestBufferInitializationFailure(t *testing.T) {
	cause := errors.New("map missing")
	reader, err := StartBuffer("exec_events", func() (Buffer, error) { return nil, cause })
	if reader != nil || !errors.Is(err, cause) || !strings.Contains(err.Error(), "exec_events") {
		t.Fatalf("reader=%v err=%v", reader, err)
	}
	if _, err = StartBuffer("nil", func() (Buffer, error) { return nil, nil }); err == nil {
		t.Fatal("nil buffer accepted")
	}
}

func TestBufferStartsOnlyAfterInitialization(t *testing.T) {
	buffer := new(fakeBuffer)
	reader, err := StartBuffer("events", func() (Buffer, error) {
		if buffer.starts != 0 {
			t.Fatal("started before initialization")
		}
		return buffer, nil
	})
	if err != nil || reader != buffer || buffer.starts != 1 {
		t.Fatalf("reader=%v starts=%d err=%v", reader, buffer.starts, err)
	}
}
