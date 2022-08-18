package chanutils

import "sync/atomic"

const (
	// DefaultQueueSize is the default size to use for concurrent queues.
	DefaultQueueSize = 10
)

var (
	// nextID is the next subscription ID that will be used for a new event
	// receiver. This MUST be used atomically.
	nextID uint64
)

// EventReceiver is a struct type that holds two queues for new and removed
// items respectively.
type EventReceiver[T any] struct {
	// id is the internal process-unique ID of the subscription.
	id uint64

	// NewItemCreated is sent to when a new item was created successfully.
	NewItemCreated *ConcurrentQueue[T]

	// ItemRemoved is sent to when an existing item was removed.
	ItemRemoved *ConcurrentQueue[T]
}

// ID returns the internal process-unique ID of the subscription.
func (e *EventReceiver[T]) ID() uint64 {
	return e.id
}

// Stop stops the receiver from processing events.
func (e *EventReceiver[T]) Stop() {
	e.NewItemCreated.Stop()
	e.ItemRemoved.Stop()
}

// NewEventReceiver creates a new event receiver with concurrent queues of the
// given size.
func NewEventReceiver[T any](queueSize int) *EventReceiver[T] {
	created := NewConcurrentQueue[T](queueSize)
	created.Start()
	removed := NewConcurrentQueue[T](queueSize)
	removed.Start()

	id := atomic.AddUint64(&nextID, 1)

	return &EventReceiver[T]{
		id:             id,
		NewItemCreated: created,
		ItemRemoved:    removed,
	}
}

// EventPublisher is an interface type for a component that offers event based
// subscriptions for publishing events.
type EventPublisher[T any, Q any] interface {
	// RegisterSubscriber adds a new subscriber for receiving events. The
	// deliverExisting boolean indicates whether already existing items
	// should be sent to the NewItemCreated channel when the subscription is
	// started. An optional deliverFrom can be specified to indicate from
	// which timestamp/index/marker onward existing items should be
	// delivered on startup. If deliverFrom is nil/zero/empty then all
	// existing items will be delivered.
	RegisterSubscriber(receiver *EventReceiver[T], deliverExisting bool,
		deliverFrom Q) error

	// RemoveSubscriber removes the given subscriber and also stops it from
	// processing events.
	RemoveSubscriber(subscriber *EventReceiver[T]) error
}
