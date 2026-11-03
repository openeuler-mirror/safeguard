package helpers

import (
	"testing"
	"time"
)

func TestConsumersWaitForInFlightHandler(t *testing.T) {
	var consumers Consumers
	received, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	consumers.Go(func() { close(received); <-release })
	<-received
	go func() { consumers.Wait(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("returned before handler completed")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
}

func TestLostDrainDoesNotBlockProducer(t *testing.T) {
	var consumers Consumers
	lost := make(chan uint64)
	consumers.Go(func() { DrainLost(lost) })
	for i := 0; i < 10; i++ {
		lost <- 1
	}
	close(lost)
	consumers.Wait()
}
