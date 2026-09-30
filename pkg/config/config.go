// Package config reads a service's settings from the environment, once, at
// start. It is the only place a service looks at its environment, and it
// collects every missing setting before failing so a misconfigured deploy
// reports all of them at once.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env reads settings and remembers what was missing or malformed.
type Env struct {
	problems []string
}

func (e *Env) lookup(name string) (string, bool) {
	value, ok := os.LookupEnv(name)
	value = strings.TrimSpace(value)
	return value, ok && value != ""
}

// String is the setting, or fallback when it is unset.
func (e *Env) String(name, fallback string) string {
	if value, ok := e.lookup(name); ok {
		return value
	}
	return fallback
}

// Required is the setting, recorded as a problem when it is unset.
func (e *Env) Required(name string) string {
	value, ok := e.lookup(name)
	if !ok {
		e.problems = append(e.problems, name+" is not set")
	}
	return value
}

// Int is the setting as an integer, or fallback when it is unset.
func (e *Env) Int(name string, fallback int) int {
	value, ok := e.lookup(name)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		e.problems = append(e.problems, fmt.Sprintf("%s: %q is not a whole number", name, value))
		return fallback
	}
	return n
}

// Bool is true for "true", false for "false", or fallback when it is unset.
func (e *Env) Bool(name string, fallback bool) bool {
	value, ok := e.lookup(name)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		e.problems = append(e.problems, fmt.Sprintf("%s: %q is not true or false", name, value))
		return fallback
	}
	return b
}

// Duration is the setting as a Go duration ("30s"), or fallback when unset.
func (e *Env) Duration(name string, fallback time.Duration) time.Duration {
	value, ok := e.lookup(name)
	if !ok {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		e.problems = append(e.problems, fmt.Sprintf("%s: %q is not a duration like 30s", name, value))
		return fallback
	}
	return d
}

// Err is every problem found so far, or nil.
func (e *Env) Err() error {
	if len(e.problems) == 0 {
		return nil
	}
	return errors.New("config: " + strings.Join(e.problems, "; "))
}

// Lookup is the setting, or empty when it is unset: for a setting whose name
// is only known at run time, such as a data owner's <NAME>_URL.
func (e *Env) Lookup(name string) string { return e.String(name, "") }
