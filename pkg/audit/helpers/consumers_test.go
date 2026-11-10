package helpers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
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

func TestLostDrainReportsNonzeroCounts(t *testing.T) {
	lost := make(chan uint64, 3)
	lost <- 3
	lost <- 0
	lost <- 7
	close(lost)
	var counts []uint64
	drainLost(lost, func(count uint64) { counts = append(counts, count) })
	if len(counts) != 2 || counts[0] != 3 || counts[1] != 7 {
		t.Fatalf("unexpected loss counts: %v", counts)
	}
}

func TestReportLostIncludesModuleAndCount(t *testing.T) {
	logger := logrus.StandardLogger()
	previousOutput, previousLevel := logger.Out, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetLevel(logrus.InfoLevel)
	t.Cleanup(func() { logger.SetOutput(previousOutput); logger.SetLevel(previousLevel) })
	lost := make(chan uint64, 1)
	lost <- 42
	close(lost)
	ReportLost(lost, "mount")
	if !bytes.Contains(output.Bytes(), []byte("mount audit lost 42 events")) {
		t.Fatalf("missing loss information: %s", output.String())
	}
}

func TestConsumerFailureRequestsShutdown(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprint(panics), func(t *testing.T) {
			var consumers Consumers
			cause := errors.New("sink failure")
			consumers.Go(func() {
				if panics {
					panic(cause)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			consumers.Await(ctx)
			if ctx.Err() != nil {
				t.Fatal("consumer failure did not wake module")
			}
			err := consumers.Wait()
			if panics && !errors.Is(err, cause) {
				t.Fatalf("lost panic cause: %v", err)
			}
			if !panics && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("unexpected close: %v", err)
			}
		})
	}
}

func TestConsumerNormalShutdown(t *testing.T) {
	var consumers Consumers
	stop := make(chan struct{})
	consumers.Go(func() { <-stop })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	consumers.Await(ctx)
	close(stop)
	if err := consumers.Wait(); err != nil {
		t.Fatal(err)
	}
}
