// Command stubissuer mints tokens for local development, until the
// identity service issues real ones.
//
// It refuses to start unless STUB_ISSUER_LOCAL_ONLY=true, which only the
// compose stack sets. Its keys are generated at start, so restarting it
// invalidates every token it issued.
//
//	curl -X POST localhost:8090/token -d '{"org_id":"<uuid>"}'
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	env := &config.Env{}
	var (
		localOnly = env.Bool("STUB_ISSUER_LOCAL_ONLY", false)
		port      = env.Int("PORT", 8090)
		// The product's name and id; the id is the default token audience.
		brand    = config.BrandFrom(env)
		issuer   = env.String("AUTH_ISSUER", brand.ID+"-local-stub")
		audience = env.String("AUTH_AUDIENCE", brand.ID)
		origins  = env.String("ALLOWED_ORIGINS", "")
	)
	if err := env.Err(); err != nil {
		return err
	}
	// A product's own services (pkg/dataowner), so their service tokens are
	// accepted here.
	if err := dataowner.Default.Load(env.String("DATA_OWNERS", "")); err != nil {
		return fmt.Errorf("DATA_OWNERS: %w", err)
	}
	if !localOnly {
		return fmt.Errorf("stubissuer signs a token for anyone who asks; set STUB_ISSUER_LOCAL_ONLY=true to run it locally")
	}
	logger := logging.New("stubissuer", "info")

	iss, err := stubissuer.New(issuer, audience)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	handler := corsFor(splitOrigins(origins), iss.Handler())
	return httpx.Serve(ctx, logger, fmt.Sprintf(":%d", port), httpx.Logged(logger, handler), 5*time.Second)
}

// corsFor lets the frontend's dev server ask for a token from the browser.
func corsFor(origins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && slices.Contains(origins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func splitOrigins(s string) []string {
	var out []string
	for _, o := range strings.Split(s, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}
