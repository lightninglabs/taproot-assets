package chanutils

import (
	"context"
	"sync"
	"time"
)

// ContextGuard is an embeddable struct that provides a wait group and main quit
// channel that can be used to create guarded contexts.
type ContextGuard struct {
	DefaultTimeout time.Duration
	Wg             sync.WaitGroup
	Quit           chan struct{}
}

// WithCtxQuit is used to create a cancellable context that will be cancelled
// if the main quit signal is triggered or after the default timeout occurred.
func (g *ContextGuard) WithCtxQuit() (context.Context, func()) {
	return g.WithCtxQuitCustomTimeout(g.DefaultTimeout)
}

// WithCtxQuitCustomTimeout is used to create a cancellable context that will be
// cancelled if the main quit signal is triggered or after the given timeout
// occurred.
func (g *ContextGuard) WithCtxQuitCustomTimeout(
	timeout time.Duration) (context.Context, func()) {

	timeoutTimer := time.NewTimer(timeout)
	ctx, cancel := context.WithCancel(context.Background())

	g.Wg.Add(1)
	go func() {
		defer timeoutTimer.Stop()
		defer cancel()
		defer g.Wg.Done()

		select {
		case <-g.Quit:

		case <-timeoutTimer.C:

		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// WithCtxQuitNoTimeout is used to create a cancellable context that will be
// cancelled if the main quit signal is triggered.
func (g *ContextGuard) WithCtxQuitNoTimeout() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())

	g.Wg.Add(1)
	go func() {
		defer cancel()
		defer g.Wg.Done()

		select {
		case <-g.Quit:

		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}
