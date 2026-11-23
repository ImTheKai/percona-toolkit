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

// Formatting helpers. These are ports of the report_formatting bash package
// used by pt-summary (lib/bash/report_formatting.sh) so that the output of
// pt-windows-summary looks and rounds exactly like the output of pt-summary.

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// writer wraps an io.Writer with the pt-summary formatting primitives.
type writer struct {
	w          io.Writer
	nameValLen int
}

func newWriter(w io.Writer) *writer {
	return &writer{w: w, nameValLen: 12}
}

func (w *writer) printf(format string, args ...interface{}) {
	fmt.Fprintf(w.w, format, args...)
}

func (w *writer) println(s string) {
	fmt.Fprintln(w.w, s)
}

// section prints a section header, e.g.
// # Processor ##################################################
func (w *writer) section(title string) {
	fmt.Fprintln(w.w, sectionLine(title))
}

func sectionLine(title string) string {
	n := 60 - len(title) - 1
	if n < 1 {
		n = 1
	}
	return "# " + title + " " + strings.Repeat("#", n)
}

// nameVal prints a right aligned name, a pipe, and the value.
func (w *writer) nameVal(name, val string) {
	fmt.Fprintf(w.w, "%*s | %s\n", w.nameValLen, name, val)
}

// withNameValLen runs f with a temporary name column width.
func (w *writer) withNameValLen(n int, f func()) {
	orig := w.nameValLen
	w.nameValLen = n
	defer func() { w.nameValLen = orig }()
	f()
}

// shorten converts a number of bytes to a human readable form using the
// same thresholds and precision as pt-summary's shorten().
func shorten(num float64, prec int) string {
	unit := ""
	switch {
	case num >= 1125899906842624:
		unit = "P"
	case num >= 1099511627776:
		unit = "T"
	case num >= 1073741824:
		unit = "G"
	case num >= 1048576:
		unit = "M"
	case num >= 1024:
		unit = "k"
	}
	for num >= 1024 {
		num /= 1024
	}
	return fmt.Sprintf("%.*f%s", prec, num, unit)
}

func shortenU(num uint64, prec int) string {
	return shorten(float64(num), prec)
}

// fuzz implements pt-summary's "fuzzy rounding": it rounds to the nearest 5,
// then 10, then 25, then repeats by a factor of 10 larger (50, 100, 250), ...
func fuzz(v float64) int64 {
	if v <= 10 {
		return int64(math.Round(v))
	}
	factor := 1.0
	for {
		switch {
		case v <= 50*factor:
			return int64(math.RoundToEven(v/(5*factor)) * 5 * factor)
		case v <= 100*factor:
			return int64(math.RoundToEven(v/(10*factor)) * 10 * factor)
		case v <= 250*factor:
			return int64(math.RoundToEven(v/(25*factor)) * 25 * factor)
		}
		factor *= 10
	}
}

// fuzzyPct returns the fuzzy rounded percentage of one over two.
func fuzzyPct(one, two float64) string {
	pct := 0.0
	if two > 0 {
		pct = math.Trunc(one / two * 100)
	}
	return fmt.Sprintf("%d%%", fuzz(pct))
}

// groupConcat renders counted values the way pt-summary does: "2x foo, 1x bar".
// The order is stable: values sorted lexically like `sort | uniq -c`.
func groupConcat(values []string) string {
	counts := map[string]int{}
	for _, v := range values {
		counts[v]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%dx%s", counts[k], k))
	}
	return strings.Join(parts, ", ")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// truncate shortens s to at most n runes.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "~"
}

// formatDuration formats an uptime like the uptime(1) command does.
func formatUptime(seconds int64) string {
	if seconds < 0 {
		seconds = 0
	}
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	mins := (seconds % 3600) / 60
	var b strings.Builder
	switch {
	case days == 1:
		b.WriteString("1 day, ")
	case days > 1:
		fmt.Fprintf(&b, "%d days, ", days)
	}
	if hours > 0 {
		fmt.Fprintf(&b, "%2d:%02d", hours, mins)
	} else {
		fmt.Fprintf(&b, "%d min", mins)
	}
	return b.String()
}
