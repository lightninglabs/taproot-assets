package tapreorg

import "sync"

// DeliveryWaiters tracks the anchorings a subsystem is waiting on
// outcomes for, so that the watcher's delivery listener can wake a
// waiter the moment a phase is delivered. The registry remains the
// durable source of the outcome: a waiter obtains its channel, reads
// the registry, and only then blocks, and the channel is buffered, so
// a delivery landing between the read and the wait is never lost.
// Latency path only.
type DeliveryWaiters struct {
	mu      sync.Mutex
	waiters map[AnchoringID]chan struct{}
}

// NewDeliveryWaiters returns an empty waiter set.
func NewDeliveryWaiters() *DeliveryWaiters {
	return &DeliveryWaiters{
		waiters: make(map[AnchoringID]chan struct{}),
	}
}

// Channel returns the nudge channel for an anchoring, creating it if
// the anchoring has no waiter yet.
func (w *DeliveryWaiters) Channel(id AnchoringID) <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()

	ch, ok := w.waiters[id]
	if !ok {
		ch = make(chan struct{}, 1)
		w.waiters[id] = ch
	}

	return ch
}

// Nudge wakes an anchoring's waiter, if any.
func (w *DeliveryWaiters) Nudge(id AnchoringID) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if ch, ok := w.waiters[id]; ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Forget drops an anchoring's waiter.
func (w *DeliveryWaiters) Forget(id AnchoringID) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.waiters, id)
}
