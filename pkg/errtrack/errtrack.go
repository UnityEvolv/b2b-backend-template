// Package errtrack sends unhandled errors to Sentry with enough context to
// debug them: the service, the release, the environment, the org and
// user ids and the request id. Never a name, an email, a token or a body.
//
// It is wired once per service in main, and everything else reaches it
// through the logger: a record at Error level is an event, and a Warn record
// carrying alert=true is too (rate-limit hits, a provider unreachable). A
// panic in a request is captured with its stack.
package errtrack

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
)

// release is set at build time: -ldflags "-X .../pkg/errtrack.release=<sha>".
var release string

// Options is what a service tells Sentry about itself.
type Options struct {
	// DSN from configuration. Empty disables tracking; nothing else changes.
	DSN         string
	Environment string
	Service     string
	// Transport overrides where events go, for tests.
	Transport sentry.Transport
}

var enabled bool

// Init starts tracking. The returned flush sends what is buffered; call it
// before the process exits.
func Init(o Options) (flush func(), err error) {
	if o.DSN == "" {
		enabled = false
		return func() {}, nil
	}
	err = sentry.Init(sentry.ClientOptions{
		Dsn:              o.DSN,
		Environment:      o.Environment,
		Release:          Release(),
		ServerName:       o.Service,
		AttachStacktrace: true,
		// Never: no request bodies, no cookies, no user email or address.
		SendDefaultPII: false,
		EnableTracing:  false,
		Tags:           map[string]string{"service": o.Service},
		BeforeSend:     scrub,
		Transport:      o.Transport,
	})
	if err != nil {
		return func() {}, fmt.Errorf("errtrack: %w", err)
	}
	enabled = true
	return func() { sentry.Flush(2 * time.Second) }, nil
}

// Enabled reports whether events are being sent.
func Enabled() bool { return enabled }

// Release is the build's identity: the commit set at build time, else the
// module's VCS revision, else "dev".
func Release() string {
	if release != "" {
		return release
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return s.Value[:7]
			}
		}
	}
	return "dev"
}

// scrub removes what must never leave: authorization and cookies from any
// request attached, and anything that looks like a person.
func scrub(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event.Request != nil {
		event.Request.Cookies = ""
		event.Request.Data = ""
		for name := range event.Request.Headers {
			switch strings.ToLower(name) {
			case "authorization", "cookie", "set-cookie", "x-api-key":
				delete(event.Request.Headers, name)
			}
		}
	}
	if event.User.Email != "" || event.User.IPAddress != "" || event.User.Name != "" || event.User.Username != "" {
		event.User = sentry.User{ID: event.User.ID}
	}
	return event
}

type tagsKey struct{}

// WithTags returns a context whose events carry tags: the request id from
// the HTTP middleware, the org, user, membership or service from auth. Values
// are ids, never PII.
func WithTags(ctx context.Context, tags map[string]string) context.Context {
	merged := map[string]string{}
	for k, v := range TagsFrom(ctx) {
		merged[k] = v
	}
	for k, v := range tags {
		if v != "" {
			merged[k] = v
		}
	}
	return context.WithValue(ctx, tagsKey{}, merged)
}

// TagsFrom is the tags in ctx.
func TagsFrom(ctx context.Context) map[string]string {
	tags, _ := ctx.Value(tagsKey{}).(map[string]string)
	return tags
}

func scoped(ctx context.Context) *sentry.Hub {
	hub := sentry.CurrentHub().Clone()
	tags := TagsFrom(ctx)
	hub.ConfigureScope(func(scope *sentry.Scope) {
		for k, v := range tags {
			scope.SetTag(k, v)
		}
		if id := tags["user_id"]; id != "" {
			scope.SetUser(sentry.User{ID: id})
		}
	})
	return hub
}

// Capture sends err as an event with ctx's tags.
func Capture(ctx context.Context, err error) {
	if !enabled || err == nil {
		return
	}
	scoped(ctx).CaptureException(err)
}

// CapturePanic sends a recovered panic with its stack.
func CapturePanic(ctx context.Context, recovered any) {
	if !enabled || recovered == nil {
		return
	}
	err, ok := recovered.(error)
	if !ok {
		err = fmt.Errorf("panic: %v", recovered)
	}
	scoped(ctx).CaptureException(err)
}

// Message sends a message at level with ctx's tags and extra tags.
func Message(ctx context.Context, level sentry.Level, msg string, tags map[string]string) {
	if !enabled {
		return
	}
	hub := scoped(ctx)
	hub.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetLevel(level)
		for k, v := range tags {
			scope.SetTag(k, v)
		}
	})
	hub.CaptureMessage(msg)
}

// Handler forwards log records to Sentry: every Error, and any Warn that
// carries alert=true. Everything still goes to the wrapped handler.
func Handler(next slog.Handler) slog.Handler { return &forwarding{next: next} }

type forwarding struct {
	next  slog.Handler
	attrs []slog.Attr
}

func (f *forwarding) Enabled(ctx context.Context, level slog.Level) bool {
	return f.next.Enabled(ctx, level)
}

func (f *forwarding) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &forwarding{next: f.next.WithAttrs(attrs), attrs: append(append([]slog.Attr{}, f.attrs...), attrs...)}
}

func (f *forwarding) WithGroup(name string) slog.Handler {
	return &forwarding{next: f.next.WithGroup(name), attrs: f.attrs}
}

func (f *forwarding) Handle(ctx context.Context, r slog.Record) error {
	if enabled {
		tags := map[string]string{}
		alert := false
		var errValue error
		collect := func(a slog.Attr) bool {
			switch a.Key {
			case "alert":
				alert = a.Value.Kind() == slog.KindBool && a.Value.Bool()
			case "error":
				if e, ok := a.Value.Any().(error); ok {
					errValue = e
				} else {
					tags["error"] = truncate(a.Value.String())
				}
			case "stack", "panic":
				// The stack is already in the message for a panic; not a tag.
			default:
				tags[a.Key] = truncate(a.Value.String())
			}
			return true
		}
		for _, a := range f.attrs {
			collect(a)
		}
		r.Attrs(collect)

		switch {
		case r.Level >= slog.LevelError:
			if errValue != nil {
				Message(ctx, sentry.LevelError, r.Message+": "+errValue.Error(), tags)
			} else {
				Message(ctx, sentry.LevelError, r.Message, tags)
			}
		case r.Level == slog.LevelWarn && alert:
			Message(ctx, sentry.LevelWarning, r.Message, tags)
		}
	}
	return f.next.Handle(ctx, r)
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
