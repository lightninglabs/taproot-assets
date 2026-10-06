package proof

import "context"

type progressCallbackKey struct{}

// WithProgressCallback returns a child context that reports successful proof
// fetch and verification steps through the given callback.
func WithProgressCallback(ctx context.Context,
	callback func()) context.Context {

	if callback == nil {
		return ctx
	}

	return context.WithValue(ctx, progressCallbackKey{}, callback)
}

// ReportProgress reports a successful proof fetch or verification step to a
// callback attached to the context, if present.
func ReportProgress(ctx context.Context) {
	callback, ok := ctx.Value(progressCallbackKey{}).(func())
	if ok {
		callback()
	}
}
