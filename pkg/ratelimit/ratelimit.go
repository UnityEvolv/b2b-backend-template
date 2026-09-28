// Package ratelimit is the one rate limiter every service uses (UO-119).
//
// A Rule is "limit requests per window", enforced in Redis so every node
// shares the count. The realtime service runs the same Lua script, so a limit
// means the same thing on a socket as over HTTP.
package ratelimit

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

//go:embed gcra.lua
var gcraSource string

// Script is the GCRA script, exported so tests can compare copies.
var Script = gcraSource

// Rule is a limit: Limit requests per Window, bursts of up to Limit allowed.
type Rule struct {
	// Name keys the bucket, so two rules never share a count.
	Name   string
	Limit  int
	Window time.Duration
	// FailClosed refuses requests when Redis is unreachable. The default,
	// fail-open, keeps the product working through a Redis blip; sign-in and
	// anything an attacker would target on purpose should fail closed.
	FailClosed bool
}

// Verdict is the answer for one request.
type Verdict struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Limiter checks rules against Redis.
type Limiter struct {
	rdb    redis.Scripter
	script *redis.Script
	logger *slog.Logger
}

// New is a limiter on rdb.
func New(rdb redis.Scripter, logger *slog.Logger) *Limiter {
	return &Limiter{rdb: rdb, script: redis.NewScript(gcraSource), logger: logger}
}

// ErrUnavailable means Redis could not be reached and the rule fails closed.
var ErrUnavailable = errors.New("ratelimit: unavailable")

// Take spends one request from key's bucket under rule.
func (l *Limiter) Take(ctx context.Context, rule Rule, key string) (Verdict, error) {
	return l.take(ctx, rule, key, 1)
}

// Check answers whether key could spend one now, without spending it. With
// Penalize, it limits failures only: check before a sign-in attempt, penalize
// when it fails, so a person who types their password right is never slowed.
func (l *Limiter) Check(ctx context.Context, rule Rule, key string) (Verdict, error) {
	return l.take(ctx, rule, key, 0)
}

// Penalize spends one request from key's bucket, for a failure.
func (l *Limiter) Penalize(ctx context.Context, rule Rule, key string) (Verdict, error) {
	return l.take(ctx, rule, key, 1)
}

func (l *Limiter) take(ctx context.Context, rule Rule, key string, cost int) (Verdict, error) {
	if rule.Limit <= 0 || rule.Window <= 0 || rule.Name == "" {
		return Verdict{}, fmt.Errorf("ratelimit: rule %q is not a limit", rule.Name)
	}
	reply, err := l.script.Run(ctx, l.rdb, []string{"rl:" + rule.Name + ":" + key},
		rule.Limit, rule.Window.Milliseconds(), cost).Int64Slice()
	if err != nil {
		l.logger.Error("rate limiter unreachable", "rule", rule.Name, "fail_closed", rule.FailClosed, "error", err)
		if rule.FailClosed {
			return Verdict{}, ErrUnavailable
		}
		return Verdict{Allowed: true, Remaining: rule.Limit}, nil
	}
	return Verdict{
		Allowed:    reply[0] == 1,
		Remaining:  int(reply[1]),
		RetryAfter: time.Duration(reply[2]) * time.Millisecond,
	}, nil
}

// WithBypass marks ctx as an internal service-to-service call, which no
// limit applies to. Only the internal-call authentication sets it; nothing a
// client sends can.
func WithBypass(ctx context.Context) context.Context { return httpx.WithInternalCall(ctx) }

// Bypassed reports whether ctx is exempt.
func Bypassed(ctx context.Context) bool { return httpx.IsInternalCall(ctx) }
