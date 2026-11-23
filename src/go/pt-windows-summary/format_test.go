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
	"bytes"
	"testing"
)

// The expected values below were produced by the bash implementations in
// bin/pt-summary (fuzz, fuzzy_pct, shorten, section), so these tests guarantee
// that both tools round and format numbers identically.

func TestFuzzMatchesPtSummary(t *testing.T) {
	cases := map[float64]int64{
		0: 0, 3: 3, 10: 10, 11: 10, 12: 10, 13: 15, 17: 15, 23: 25, 48: 50, 52: 50,
		77: 80, 99: 100, 101: 100, 130: 125, 137: 125, 249: 250, 251: 250, 501: 500,
		777: 800, 1234: 1250, 9999: 10000, 12345: 12500, 98765: 100000, 123456: 125000,
		7000000: 7000000, 1987654321: 2000000000,
	}
	for in, want := range cases {
		if got := fuzz(in); got != want {
			t.Errorf("fuzz(%v) = %d, want %d", in, got, want)
		}
	}
}

func TestFuzzyPctMatchesPtSummary(t *testing.T) {
	cases := []struct {
		one, two float64
		want     string
	}{
		{1, 3, "35%"}, {2, 3, "70%"}, {50, 100, "50%"}, {7, 9, "80%"}, {0, 0, "0%"}, {123, 456, "25%"},
	}
	for _, c := range cases {
		if got := fuzzyPct(c.one, c.two); got != c.want {
			t.Errorf("fuzzyPct(%v, %v) = %q, want %q", c.one, c.two, got, c.want)
		}
	}
}

func TestShortenMatchesPtSummary(t *testing.T) {
	cases := []struct {
		n          float64
		p1, p0, p2 string
	}{
		{0, "0.0", "0", "0.00"},
		{1023, "1023.0", "1023", "1023.00"},
		{1024, "1.0k", "1k", "1.00k"},
		{1536, "1.5k", "2k", "1.50k"},
		{1048575, "1024.0k", "1024k", "1024.00k"},
		{1048576, "1.0M", "1M", "1.00M"},
		{1059061760, "1010.0M", "1010M", "1010.00M"},
		{1073741824, "1.0G", "1G", "1.00G"},
		{1099511627776, "1.0T", "1T", "1.00T"},
		{5629499534213120, "5.0P", "5P", "5.00P"},
	}
	for _, c := range cases {
		for prec, want := range map[int]string{1: c.p1, 0: c.p0, 2: c.p2} {
			if got := shorten(c.n, prec); got != want {
				t.Errorf("shorten(%v, %d) = %q, want %q", c.n, prec, got, want)
			}
		}
	}
}

func TestSectionMatchesPtSummary(t *testing.T) {
	cases := map[string]string{
		"Processor":                                         "# Processor ##################################################",
		"Percona Toolkit System Summary Report":             "# Percona Toolkit System Summary Report ######################",
		"Simplified and fuzzy rounded vmstat (wait please)": "# Simplified and fuzzy rounded vmstat (wait please) ##########",
		"A very long title that is definitely longer than sixty characters in total": "# A very long title that is definitely longer than sixty characters in total #",
	}
	for in, want := range cases {
		if got := sectionLine(in); got != want {
			t.Errorf("section(%q)\n got: %q\nwant: %q", in, got, want)
		}
	}
}

func TestNameVal(t *testing.T) {
	var b bytes.Buffer
	w := newWriter(&b)
	w.nameVal("Hostname", "db1")
	w.withNameValLen(14, func() { w.nameVal("Total", "1.0G") })
	w.nameVal("Kernel", "10.0")
	want := "    Hostname | db1\n         Total | 1.0G\n      Kernel | 10.0\n"
	if b.String() != want {
		t.Errorf("got %q, want %q", b.String(), want)
	}
}

func TestGroupConcat(t *testing.T) {
	got := groupConcat([]string{"b", "a", "b", "b"})
	if want := "1xa, 3xb"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := groupConcat(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestFormatUptime(t *testing.T) {
	cases := map[int64]string{
		59:             "0 min",
		38 * 60:        "38 min",
		3600 + 4*60:    " 1:04",
		86400 + 20*60:  "1 day, 20 min",
		3*86400 + 7260: "3 days,  2:01",
		-5:             "0 min",
	}
	for in, want := range cases {
		if got := formatUptime(in); got != want {
			t.Errorf("formatUptime(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("NT AUTHORITY\\NETWORK SERVICE", 10); got != "NT AUTHOR~" {
		t.Errorf("got %q", got)
	}
	if got := truncate("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
}
