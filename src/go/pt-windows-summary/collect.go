// This program is copyright 2026 Percona LLC and/or its affiliates.
//
// THIS PROGRAM IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 2.
//
// You should have received a copy of the GNU General Public License, version 2
// along with this program; if not, see <https://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// defaultCollectorTimeout bounds every individual collector. WMI providers
// can hang on unhealthy systems; one stuck provider must not prevent the rest
// of the report from being produced.
const defaultCollectorTimeout = 60 * time.Second

var ptDebug = os.Getenv("PTDEBUG") != ""

func debugf(format string, args ...interface{}) {
	if ptDebug {
		fmt.Fprintf(os.Stderr, "# %s pt-windows-summary: %s\n",
			time.Now().Format("2006-01-02T15:04:05"), fmt.Sprintf(format, args...))
	}
}

// run executes a collector in its own goroutine with a timeout. Collectors
// return their result rather than writing into shared state, so a collector
// that times out and keeps running in the background can't race with the
// report. A collector may return a partial result together with an error.
func run[T any](s *Samples, name string, timeout time.Duration, fn func() (T, error)) T {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	start := time.Now()
	debugf("collector %s: start", name)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				var zero T
				ch <- result{zero, fmt.Errorf("internal error: %v", r)}
			}
		}()
		v, err := fn()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		debugf("collector %s: done in %s (err: %v)", name, time.Since(start).Round(time.Millisecond), r.err)
		s.addError(name, r.err)
		return r.v
	case <-time.After(timeout):
		debugf("collector %s: timed out", name)
		s.addError(name, fmt.Errorf("timed out after %s", timeout))
		var zero T
		return zero
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// joinErrs combines several non-fatal errors into one, or returns nil.
func joinErrs(errs []error) error {
	var msgs []string
	for _, e := range errs {
		if e != nil {
			msgs = append(msgs, e.Error())
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}
