//go:build !dev

package rfqmsg

// SetNoopAdd flags the HTLC as a noop_add.
func (h *Htlc) SetNoopAdd() {}
