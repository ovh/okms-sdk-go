package okms

import "context"

type ctxHeaderKey struct{}

// WithContextHeader adds some custom headers to the request's context.
func WithContextHeader(ctx context.Context, key, value string) context.Context {
	hdrs, ok := ctx.Value(ctxHeaderKey{}).(map[string]string)
	if !ok || hdrs == nil {
		hdrs = make(map[string]string)
		ctx = context.WithValue(ctx, ctxHeaderKey{}, hdrs)
	}
	hdrs[key] = value
	return ctx
}

func getContextHeaders(ctx context.Context) map[string]string {
	hdrs, _ := ctx.Value(ctxHeaderKey{}).(map[string]string)
	return hdrs
}
