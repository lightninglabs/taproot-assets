package main

type HopQueue struct {
	queue []HopList
}

func (q *HopQueue) push(newHop HopList) {
	q.queue = append(q.queue, newHop)
}

// Multi-element append
func (q *HopQueue) append(existingHops []HopList) {
	q.queue = append(q.queue, existingHops...)
}

// must be called on a non-empty queue
func (q *HopQueue) pop() HopList {
	nextHop := q.queue[0]
	if len(q.queue) == 1 {
		q.queue = make([]HopList, 0, 1)
	} else {
		q.queue = q.queue[1:]
	}
	return nextHop
}

func (q *HopQueue) empty() bool {
	return len(q.queue) == 0
}
