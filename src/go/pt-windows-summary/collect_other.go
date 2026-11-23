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

//go:build !windows

package main

import (
	"errors"
	"time"
)

// On non-Windows platforms the tool can only render reports from samples
// collected on Windows (--read-samples). Use pt-summary on Linux and Unix.
func collectAll(_ *Samples, _ time.Duration) error {
	return errors.New("pt-windows-summary can only collect data on Windows. " +
		"Use pt-summary on Linux and Unix, or --read-samples to render a report from samples collected on Windows")
}
