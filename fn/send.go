package fn

// SendOrQuit attempts to and a message through channel c. If this succeeds,
// then bool is returned. Otherwise if a quit signal is received first, then
// false is returned.
func SendOrQuit[T any, Q any](c chan<- T, msg T, quit chan Q) bool {
	select {
	case c <- msg:
		return true
	case <-quit:
		return false
	}
}

// SendAll attempts to send all messages through channel c.
//
// TODO(roasbeef): add non-blocking variant?
func SendAll[T any](c chan<- T, msgs ...T) {
	for _, msg := range msgs {
		c <- msg
	}
}
