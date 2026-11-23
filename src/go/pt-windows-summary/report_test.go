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
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update the expected report files in testdata")

// TestReportGolden renders every sample directory under testdata and compares
// the result with the expected report. Run `go test -update` to regenerate the
// expected files after an intentional output change, and review the diff.
func TestReportGolden(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("testdata", "*", samplesFile))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no samples found in testdata: %v", err)
	}
	for _, f := range dirs {
		dir := filepath.Dir(f)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			s, err := loadSamples(dir)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			report(&got, s)

			expectedFile := filepath.Join(dir, "expected.txt")
			if *update {
				if err := os.WriteFile(expectedFile, got.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(expectedFile)
			if err != nil {
				t.Fatalf("%v (run `go test -update` to create it)", err)
			}
			// Tolerate CRLF checkouts of the expected file.
			if got.String() != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Errorf("report differs from %s (run `go test -update` and review the diff):\n%s",
					expectedFile, firstDiff(string(want), got.String()))
			}
		})
	}
}

func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return "line " + strconv.Itoa(i+1) + ":\n want: " + strconv.Quote(w) + "\n  got: " + strconv.Quote(g)
		}
	}
	return ""
}

// The report must have the same skeleton as pt-summary's.
func TestReportSections(t *testing.T) {
	s, err := loadSamples(filepath.Join("testdata", "server2022"))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	report(&b, s)
	out := b.String()
	for _, sec := range []string{
		"Percona Toolkit System Summary Report", "Processor", "Memory", "Mounted Filesystems",
		"Physical Disks", "Disk Partitioning", "Kernel Object Counts", "Storage Spaces Virtual Disks",
		"Storage Spaces Pools", "RAID Controller", "Network Config", "Interface Statistics",
		"Network Devices", "Network Connections", "Top Processes", "Notable Processes",
		"Simplified and fuzzy rounded vmstat (wait please)", "Memory management", "Security",
		"Collection Errors", "The End",
	} {
		if !strings.Contains(out, sectionLine(sec)+"\n") {
			t.Errorf("section %q missing", sec)
		}
	}

	// --no-summarize-* must drop the corresponding sections, like pt-summary.
	s.Options.SummarizeMounts = false
	s.Options.SummarizeNetwork = false
	s.Options.SummarizeProcesses = false
	b.Reset()
	report(&b, s)
	out = b.String()
	for _, sec := range []string{"Mounted Filesystems", "Network Config", "Network Connections", "Top Processes", "Notable Processes"} {
		if strings.Contains(out, sectionLine(sec)) {
			t.Errorf("section %q should be skipped", sec)
		}
	}
}

func TestSamplesRoundTrip(t *testing.T) {
	s, err := loadSamples(filepath.Join("testdata", "server2022"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := saveSamples(dir, s); err != nil {
		t.Fatal(err)
	}
	s2, err := loadSamples(dir)
	if err != nil {
		t.Fatal(err)
	}
	var a, b bytes.Buffer
	report(&a, s)
	report(&b, s2)
	if a.String() != b.String() {
		t.Error("report differs after saving and loading samples")
	}
	errs, err := os.ReadFile(filepath.Join(dir, samplesErrFile))
	if err != nil || !strings.Contains(string(errs), "hotfixes: timed out") {
		t.Errorf("collect.err not written correctly: %q, %v", errs, err)
	}
}

func TestLoadSamplesErrors(t *testing.T) {
	if _, err := loadSamples(t.TempDir()); err == nil {
		t.Error("expected an error for a directory without samples")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, samplesFile), []byte(`{"format": 999}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSamples(dir); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("expected a format version error, got %v", err)
	}
}

func TestVirtualization(t *testing.T) {
	cases := []struct {
		si   SystemInfo
		want string
	}{
		{SystemInfo{Manufacturer: "Microsoft Corporation", Model: "Virtual Machine"}, "Hyper-V"},
		{SystemInfo{Manufacturer: "Microsoft Corporation", Model: "Virtual Machine", ChassisAssetTag: azureAssetTag}, "Microsoft Azure (Hyper-V)"},
		{SystemInfo{Manufacturer: "VMware, Inc.", Model: "VMware20,1"}, "VMWare"},
		{SystemInfo{Manufacturer: "Amazon EC2", Model: "m6i.xlarge"}, "Amazon EC2"},
		{SystemInfo{Manufacturer: "Xen", Model: "HVM domU", BIOSVersion: "4.11.amazon"}, "Amazon EC2"},
		{SystemInfo{Manufacturer: "Google", Model: "Google Compute Engine"}, "Google Compute Engine"},
		{SystemInfo{Manufacturer: "QEMU", Model: "Standard PC (Q35 + ICH9, 2009)"}, "KVM/QEmu"},
		{SystemInfo{Manufacturer: "Red Hat", Model: "KVM"}, "KVM/QEmu"},
		{SystemInfo{Manufacturer: "innotek GmbH", Model: "VirtualBox"}, "VirtualBox"},
		{SystemInfo{Manufacturer: "Nutanix", Model: "AHV"}, "Nutanix AHV"},
		{SystemInfo{Manufacturer: "Dell Inc.", Model: "PowerEdge R750"}, "No virtualization detected"},
		{SystemInfo{Manufacturer: "Dell Inc.", Model: "PowerEdge R750", HypervisorPresent: true},
			"No virtualization detected (Windows hypervisor is running: Hyper-V role or VBS)"},
	}
	for _, c := range cases {
		if got := virtualization(c.si); got != c.want {
			t.Errorf("virtualization(%s %s) = %q, want %q", c.si.Manufacturer, c.si.Model, got, c.want)
		}
	}
}

func TestRAIDKind(t *testing.T) {
	cases := map[string]string{
		"PERC H755 Front (Embedded)|percsas3i":                       raidMegaRAID,
		"LSI MegaRAID SAS 9361-8i|megasas2":                          raidMegaRAID,
		"AVAGO MegaRAID SAS Adapter|megasas35":                       raidMegaRAID,
		"HPE Smart Array P408i-a SR Gen10|SmartPqi":                  raidHP,
		"Smart Array P420i Controller|hpsa":                          raidHP,
		"Adaptec SmartRAID 3154-8i|arcsas":                           raidAdaptec,
		"Intel(R) Chipset SATA/PCIe RST Premium Controller|iaStorAC": raidIntel,
		"LSI Adapter, SAS3 3008 Fury -StorPort|lsi_sas3":             raidLSIHBA,
		"Standard NVM Express Controller|stornvme":                   "",
		"Microsoft Storage Spaces Controller|spaceport":              "",
		"Microsoft Hyper-V SCSI Controller|storvsc":                  "",
		"Red Hat VirtIO SCSI controller|vioscsi":                     "",
		"VMware PVSCSI Controller|pvscsi":                            "",
		"AWS NVMe Elastic Block Storage Adapter|AWSNVMe":             "",
	}
	for in, want := range cases {
		p := strings.SplitN(in, "|", 2)
		if got := raidKind(StorageController{Name: p[0], DriverName: p[1]}); got != want {
			t.Errorf("raidKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServiceImage(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe" --defaults-file="C:\ProgramData\my.ini" MySQL80`: `C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe`,
		`C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe runservice -N "postgresql-x64-16" -D "D:\pgdata"`:           `C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe`,
		`C:\Windows\system32\svchost.exe -k netsvcs -p`:                                                            `C:\Windows\system32\svchost.exe`,
		`C:\Windows\System32\OpenSSH\sshd.exe`:                                                                     `C:\Windows\System32\OpenSSH\sshd.exe`,
		`C:\tools\agent --password=secret`:                                                                         `C:\tools\agent`,
		``:                                                                                                         ``,
	}
	for in, want := range cases {
		if got := serviceImage(in); got != want {
			t.Errorf("serviceImage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHelpers(t *testing.T) {
	if got := compressRanges([]int{0, 1, 2, 3, 8, 10, 11, 64}); got != "0-3,8,10-11,64" {
		t.Errorf("compressRanges = %q", got)
	}
	if got := formatMAC("B496910000AA"); got != "b4:96:91:00:00:aa" {
		t.Errorf("formatMAC = %q", got)
	}
	if got := alignment(1 << 20); got != "1M" {
		t.Errorf("alignment(1M) = %q", got)
	}
	if got := alignment(32256); got != "NO" { // classic 63 sector MBR offset
		t.Errorf("alignment(32256) = %q", got)
	}
	if got := describeLastAccess(0x80000003); got != "updates disabled, user managed (0x80000003)" {
		t.Errorf("describeLastAccess = %q", got)
	}
	if got := describeLastAccess(0x80000001); got != "updates disabled, system managed (0x80000001)" {
		t.Errorf("describeLastAccess = %q", got)
	}
	if got := cpuTime(1554321.37); got != "25905:21.37" {
		t.Errorf("cpuTime = %q", got)
	}
	if !ipLess("10.10.1.9", "10.10.1.50") || ipLess("fd00::1", "10.0.0.1") {
		t.Error("ipLess doesn't sort numerically / IPv4 first")
	}
}
