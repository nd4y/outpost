package worker

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestWorkerCommandRunCancellationPreservesIndependentGuardFailure(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			f := newFixture(t)
			w := f.nodes[0]
			started := make(chan struct{})
			failure := errors.New("independent volume write failure")
			w.guard = func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				err := fmt.Errorf("volume admission: %w", ctx.Err())
				if mixed {
					return errors.Join(err, failure)
				}
				return errors.Join(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- w.Run(ctx) }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("guard not entered")
			}
			cancel()
			select {
			case err := <-done:
				if mixed && !errors.Is(err, failure) || !mixed && err != nil {
					t.Fatal("incorrect stop classification", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stop not joined")
			}
			w.guard = nil
		})
	}
}
