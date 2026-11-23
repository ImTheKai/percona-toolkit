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

// pt-windows-summary summarizes system information on Microsoft Windows. It is
// the Windows counterpart of pt-summary and produces a report with the same
// structure, sections and fuzzy rounding.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	"github.com/percona/percona-toolkit/src/go/lib/config"
)

const toolname = "pt-windows-summary"

// We do not set anything here, these variables are defined by the Makefile
var (
	Build     string //nolint
	GoVersion string //nolint
	Version   string //nolint
	Commit    string //nolint
)

type cliOptions struct {
	config.ConfigFlag
	ReadSamples        string           `name:"read-samples" placeholder:"DIR" help:"Create a report from the files found in this directory (as saved by --save-samples), instead of collecting data."`
	SaveSamples        string           `name:"save-samples" placeholder:"DIR" help:"Save the collected data in this directory."`
	Sleep              int              `name:"sleep" default:"5" help:"How long to sample performance counters and process CPU usage, in seconds."`
	SummarizeMounts    bool             `name:"summarize-mounts" negatable:"" default:"true" help:"Report on mounted filesystems and disk usage."`
	SummarizeNetwork   bool             `name:"summarize-network" negatable:"" default:"true" help:"Report on network controllers and configuration."`
	SummarizeProcesses bool             `name:"summarize-processes" negatable:"" default:"true" help:"Report on top processes, services and performance counters."`
	CollectorTimeout   time.Duration    `name:"collector-timeout" default:"60s" hidden:"" help:"Maximum time any single data collector may run."`
	Version            kong.VersionFlag `name:"version" help:"Show version and exit."`
}

func main() {
	opts := &cliOptions{}
	_, _, err := config.Setup(toolname, opts,
		kong.Description("Summarize system information on Windows, in the same format as pt-summary."),
		kong.UsageOnError(),
		kong.Vars{"version": fmt.Sprintf("%s\nVersion %s\nBuild: %s using %s\nCommit: %s",
			toolname, Version, Build, GoVersion, Commit)},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse command line arguments: %s\n", err)
		os.Exit(1)
	}
	if opts.Sleep < 1 {
		opts.Sleep = 1
	}

	interactive := opts.ReadSamples == "" && startedFromExplorer()
	// Show what the tool is doing when a person is watching: always when it
	// was double-clicked, and when the report is redirected to a file from
	// a console (otherwise nothing would be shown for several seconds).
	// Plain console runs, scripts and pipes stay silent, like pt-summary.
	if interactive || (opts.ReadSamples == "" && isConsole(os.Stderr) && !isConsole(os.Stdout)) {
		progressOut = os.Stderr
	}
	if interactive {
		printBanner(opts.Sleep)
	}

	var s *Samples
	if opts.ReadSamples != "" {
		s, err = loadSamples(opts.ReadSamples)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
	} else {
		s = newSamples(opts)
		if err := collectAll(s, opts.CollectorTimeout); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
	}

	if opts.SaveSamples != "" {
		if err := saveSamples(opts.SaveSamples, s); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot save samples: %s\n", err)
			os.Exit(1)
		}
	}

	if interactive {
		os.Exit(interactiveReport(s))
	}

	out := bufio.NewWriter(os.Stdout)
	report(out, s)
	if err := out.Flush(); err != nil {
		os.Exit(1)
	}
}

// interactiveReport is used when the tool was double-clicked: the console
// window would close as soon as we exit, so the report is also written to a
// file next to the executable and we wait for Enter before exiting.
func interactiveReport(s *Samples) int {
	var buf bytes.Buffer
	report(&buf, s)
	fmt.Println()
	os.Stdout.Write(buf.Bytes()) //nolint:errcheck

	name := fmt.Sprintf("%s-%s-%s.txt", toolname, sanitizeFileName(s.System.Hostname),
		s.CollectedAt.Local().Format("20060102-150405"))
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Desktop"), home)
	}
	rc := 1
	for _, dir := range dirs {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err == nil {
			fmt.Printf("\nThe report was saved to:\n  %s\n", path)
			rc = 0
			break
		}
	}
	if rc != 0 {
		fmt.Println("\nCannot save the report to a file.")
	}
	fmt.Print("\nPress Enter to close this window...")
	bufio.NewReader(os.Stdin).ReadString('\n') //nolint:errcheck
	return rc
}

func printBanner(sleep int) {
	version := Version
	if version == "" {
		version = "(development build)"
	}
	fmt.Fprintf(os.Stderr, `%s %s - Percona Toolkit

This tool creates a summary of this computer's hardware, Windows
configuration and current performance, for troubleshooting with
Percona Support. It only reads information: it doesn't change anything
on this system and doesn't send anything over the network. The report is
shown in this window and saved to a text file next to this program.

`, toolname, version)
	if !isElevated() {
		fmt.Fprint(os.Stderr, "Tip: right-click the program and choose \"Run as administrator\" for a\n"+
			"complete report. Some details can only be read by administrators.\n\n")
	}
	fmt.Fprintf(os.Stderr, "Collecting information, this takes about %d seconds...\n", sleep+10)
}

func sanitizeFileName(s string) string {
	if s == "" {
		return "host"
	}
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?* `, r) || r < 32 {
			return '_'
		}
		return r
	}, s)
}

func newSamples(opts *cliOptions) *Samples {
	now := time.Now()
	tzName, _ := now.Zone()
	return &Samples{
		Format:      samplesFormat,
		ToolVersion: Version,
		CollectedAt: now.UTC(),
		LocalTZ:     tzName + " " + now.Format("-0700"),
		Options: SampleOptions{
			SummarizeMounts:    opts.SummarizeMounts,
			SummarizeNetwork:   opts.SummarizeNetwork,
			SummarizeProcesses: opts.SummarizeProcesses,
			Sleep:              opts.Sleep,
		},
	}
}
