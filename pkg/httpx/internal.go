package httpx

import "context"

type internalCallKey struct{}

// WithInternalCall marks ctx as a call from another service, which limits
// meant for people do not apply to. Only the internal-call authentication
// sets it; nothing a client sends can.
func WithInternalCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, internalCallKey{}, true)
}

// IsInternalCall reports whether ctx is a service-to-service call.
func IsInternalCall(ctx context.Context) bool {
	v, _ := ctx.Value(internalCallKey{}).(bool)
	return v
}
