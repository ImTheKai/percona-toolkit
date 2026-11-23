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

//go:build windows

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetConsoleProcessList = modkernel32.NewProc("GetConsoleProcessList")

// startedFromExplorer reports whether the tool was started by double-clicking
// it (or with "Run as administrator" from Explorer). Windows then creates a
// console just for this process, so it is the only process attached to it,
// and the window closes as soon as the process exits.
//
// It is only true when the output goes to a console window: if stdout is
// redirected or piped, a program or script is reading the output and nobody
// could answer the "Press Enter" prompt.
func startedFromExplorer() bool {
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode) != nil {
		return false
	}
	if procGetConsoleProcessList.Find() != nil {
		return false
	}
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}
