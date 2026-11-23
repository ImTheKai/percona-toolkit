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

// Small platform independent helpers used by the Windows collectors. They
// live here so they can be unit tested on any platform.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func formatMAC(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), ":", "")
	if len(s) != 12 {
		return s
	}
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = strings.ToLower(s[i*2 : i*2+2])
	}
	return strings.Join(parts, ":")
}

var exeRe = regexp.MustCompile(`(?i)^(.*?\.exe)\b`)

// serviceImage strips the arguments from a service command line.
func serviceImage(path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, `"`) {
		if end := strings.Index(path[1:], `"`); end >= 0 {
			return path[1 : end+1]
		}
	}
	if m := exeRe.FindStringSubmatch(path); m != nil {
		return m[1]
	}
	if f := strings.Fields(path); len(f) > 0 {
		return f[0]
	}
	return ""
}

func compressRanges(n []int) string {
	if len(n) == 0 {
		return ""
	}
	var parts []string
	start, prev := n[0], n[0]
	flush := func() {
		if start == prev {
			parts = append(parts, strconv.Itoa(start))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", start, prev))
		}
	}
	for _, x := range n[1:] {
		if x == prev+1 {
			prev = x
			continue
		}
		flush()
		start, prev = x, x
	}
	flush()
	return strings.Join(parts, ",")
}
