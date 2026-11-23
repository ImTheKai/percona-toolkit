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

// The report. Sections follow pt-summary's order and formatting. Where Linux
// concepts have no Windows equivalent the section is replaced by the closest
// Windows concept (documented in README.rst):
//
//   Disk Schedulers And Queue Size -> Physical Disks
//   Kernel Inode State             -> Kernel Object Counts
//   LVM Volumes / Volume Groups    -> Storage Spaces Virtual Disks / Pools
//   Transparent huge pages         -> Large pages / Lock pages in memory
//   OOM-protected processes        -> Notable services

import (
	"fmt"
	"io"
	"math"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func report(out io.Writer, s *Samples) {
	w := newWriter(out)
	reportSystem(w, s)
	reportProcessor(w, s)
	reportMemory(w, s)
	if s.Options.SummarizeMounts {
		reportMounts(w, s)
	}
	reportDisks(w, s)
	reportKernelObjects(w, s)
	reportStorageSpaces(w, s)
	reportRAID(w, s)
	if s.Options.SummarizeNetwork {
		reportNetwork(w, s)
	}
	if s.Options.SummarizeProcesses {
		reportProcesses(w, s)
	}
	reportMemoryMgmt(w, s)
	reportSecurity(w, s)
	reportErrors(w, s)
	w.section("The End")
}

// ---- system -----------------------------------------------------------------

var chassisTypes = map[int]string{
	1: "Other", 2: "Unknown", 3: "Desktop", 4: "Low Profile Desktop", 5: "Pizza Box",
	6: "Mini Tower", 7: "Tower", 8: "Portable", 9: "Laptop", 10: "Notebook", 11: "Hand Held",
	12: "Docking Station", 13: "All in One", 14: "Sub Notebook", 15: "Space-saving",
	16: "Lunch Box", 17: "Main Server Chassis", 18: "Expansion Chassis", 19: "Sub Chassis",
	20: "Bus Expansion Chassis", 21: "Peripheral Chassis", 22: "RAID Chassis",
	23: "Rack Mount Chassis", 24: "Sealed-case PC", 25: "Multi-system", 26: "CompactPCI",
	27: "AdvancedTCA", 28: "Blade", 29: "Blade Enclosing", 30: "Tablet", 31: "Convertible",
	32: "Detachable", 33: "IoT Gateway", 34: "Embedded PC", 35: "Mini PC", 36: "Stick PC",
}

var domainRoles = map[int]string{
	0: "standalone workstation", 1: "member workstation", 2: "standalone server",
	3: "member server", 4: "backup domain controller", 5: "primary domain controller",
}

var cpuArchitectures = map[int]string{0: "x86", 5: "ARM", 6: "ia64", 9: "x64", 12: "ARM64"}

const azureAssetTag = "7783-7084-3265-9085-8269-3286-77"

// virtualization guesses the hypervisor from SMBIOS data, the same way
// pt-summary does from dmidecode/lspci/dmesg.
func virtualization(si SystemInfo) string {
	m := strings.ToLower(strings.Join([]string{si.Manufacturer, si.Model, si.BIOSVendor, si.BIOSVersion, si.ProductVersion}, " "))
	switch {
	case strings.Contains(m, "amazon ec2") || strings.Contains(m, "amazon"):
		return "Amazon EC2"
	case strings.Contains(m, "google"):
		return "Google Compute Engine"
	case strings.Contains(m, "microsoft corporation") && strings.Contains(m, "virtual machine"):
		if si.ChassisAssetTag == azureAssetTag {
			return "Microsoft Azure (Hyper-V)"
		}
		return "Hyper-V"
	case strings.Contains(m, "vmware"):
		return "VMWare"
	case strings.Contains(m, "virtualbox") || strings.Contains(m, "innotek"):
		return "VirtualBox"
	case strings.Contains(m, "nutanix"):
		return "Nutanix AHV"
	case strings.Contains(m, "openstack"):
		return "OpenStack"
	case strings.Contains(m, "parallels"):
		return "Parallels"
	case strings.Contains(m, "xen"):
		return "Xen"
	case strings.Contains(m, "qemu") || strings.Contains(m, "kvm") || strings.Contains(m, "bochs") ||
		strings.Contains(m, "red hat") || strings.Contains(m, "proxmox"):
		return "KVM/QEmu"
	}
	if si.HypervisorPresent {
		// The Windows hypervisor also runs on physical hosts with the
		// Hyper-V role or virtualization-based security enabled.
		return "No virtualization detected (Windows hypervisor is running: Hyper-V role or VBS)"
	}
	return "No virtualization detected"
}

func reportSystem(w *writer, s *Samples) {
	si := s.System
	w.section("Percona Toolkit System Summary Report")
	tz := s.LocalTZ
	if s.TimeZoneName != "" {
		tz += ", " + s.TimeZoneName
	}
	w.nameVal("Date", fmt.Sprintf("%s UTC (local TZ: %s)", s.CollectedAt.UTC().Format("2006-01-02 15:04:05"), tz))
	w.nameVal("Hostname", si.Hostname)
	if !si.LastBoot.IsZero() {
		up := int64(s.CollectedAt.Sub(si.LastBoot).Seconds())
		w.nameVal("Uptime", fmt.Sprintf("%s (since %s)", formatUptime(up), si.LastBoot.Format("2006-01-02 15:04:05 -0700")))
	} else {
		w.nameVal("Uptime", "")
	}

	if si.Manufacturer != "" {
		chassis := ""
		if len(si.ChassisTypes) > 0 {
			chassis = chassisTypes[si.ChassisTypes[0]]
		}
		system := si.Manufacturer + "; " + si.Model
		if si.ProductVersion != "" {
			system += "; v" + si.ProductVersion
		}
		if chassis != "" {
			system += " (" + chassis + ")"
		}
		w.nameVal("System", system)
		w.nameVal("Service Tag", si.SerialNumber)
	}
	if si.BIOSVendor != "" || si.BIOSVersion != "" {
		bios := strings.TrimSpace(si.BIOSVendor + " " + si.BIOSVersion)
		if si.BIOSReleaseDate != "" {
			bios += " (" + si.BIOSReleaseDate + ")"
		}
		w.nameVal("BIOS", bios)
	}
	w.nameVal("Platform", "Windows")

	release := si.OSCaption
	var extra []string
	if si.DisplayVersion != "" {
		extra = append(extra, si.DisplayVersion)
	}
	if si.InstallationType != "" && si.InstallationType != "Client" && si.InstallationType != "Server" {
		extra = append(extra, si.InstallationType)
	}
	if len(extra) > 0 {
		release += " (" + strings.Join(extra, ", ") + ")"
	}
	w.nameVal("Release", release)
	kernel := si.OSVersion
	if si.UBR > 0 {
		kernel += "." + strconv.FormatUint(uint64(si.UBR), 10)
	}
	w.nameVal("Kernel", kernel)

	cpuArch := "unknown"
	if len(s.CPU.Sockets) > 0 {
		sk := s.CPU.Sockets[0]
		cpuArch = fmt.Sprintf("%d-bit", sk.DataWidth)
		if a, ok := cpuArchitectures[sk.Architecture]; ok {
			cpuArch += " (" + a + ")"
		}
	}
	osArch := "unknown"
	switch strings.ToUpper(si.NativeArch) {
	case "AMD64", "ARM64", "IA64":
		osArch = "64-bit (" + si.NativeArch + ")"
	case "X86", "ARM":
		osArch = "32-bit (" + si.NativeArch + ")"
	}
	w.nameVal("Architecture", fmt.Sprintf("CPU = %s, OS = %s", cpuArch, osArch))
	w.nameVal("Virtualized", virtualization(si))

	if si.Domain != "" {
		kind := "domain"
		if !si.PartOfDomain {
			kind = "workgroup"
		}
		w.nameVal("Domain", fmt.Sprintf("%s (%s, %s)", si.Domain, kind, domainRoles[si.DomainRole]))
	}
	if si.TimeSyncType != "" {
		w.nameVal("Time Sync", describeTimeSync(si.TimeSyncType, si.TimeSyncServer))
	}
	if si.LastHotfixID != "" {
		w.nameVal("Last Update", fmt.Sprintf("%s installed %s (%d updates listed)", si.LastHotfixID, si.LastHotfixInstalled, si.HotfixCount))
	}
	if len(si.PendingReboot) > 0 {
		w.nameVal("Reboot", "pending ("+strings.Join(si.PendingReboot, ", ")+")")
	} else {
		w.nameVal("Reboot", "not pending")
	}
	if si.Elevated {
		w.nameVal("Privileges", "administrator (elevated)")
	} else {
		w.nameVal("Privileges", "standard user, some information may be missing; run as administrator for a complete report")
	}
}

func describeTimeSync(typ, server string) string {
	switch strings.ToUpper(typ) {
	case "NTP":
		return "NTP (" + server + ")"
	case "NT5DS":
		return "domain hierarchy (NT5DS)"
	case "ALLSYNC":
		return "NTP (" + server + ") and domain hierarchy (AllSync)"
	case "NOSYNC":
		return "disabled (NoSync)"
	}
	return typ
}

// ---- processor --------------------------------------------------------------

var cacheAssociativity = map[int]string{
	1: "Other", 2: "Unknown", 3: "Direct Mapped", 4: "2-way Set-associative",
	5: "4-way Set-associative", 6: "Fully Associative", 7: "8-way Set-associative",
	8: "16-way Set-associative", 9: "12-way Set-associative", 10: "24-way Set-associative",
	11: "32-way Set-associative", 12: "48-way Set-associative", 13: "64-way Set-associative",
	14: "20-way Set-associative",
}
var cacheTypes = map[int]string{3: "Instruction", 4: "Data", 5: "Unified"}
var cacheWritePolicies = map[int]string{3: "Write Back", 4: "Write Through", 5: "Varies With Memory Address", 6: "Determination Per I/O"}

func reportProcessor(w *writer, s *Samples) {
	w.section("Processor")
	ci := s.CPU
	physical, cores, virtual := len(ci.Sockets), 0, 0
	var speeds, models, caches []string
	maxDiffers := false
	var maxSpeeds []string
	for _, sk := range ci.Sockets {
		cores += sk.Cores
		virtual += sk.Logical
		cache := sk.L3KB
		if cache == 0 {
			cache = sk.L2KB
		}
		for i := 0; i < sk.Logical; i++ {
			speeds = append(speeds, strconv.Itoa(sk.CurrentMHz))
			maxSpeeds = append(maxSpeeds, strconv.Itoa(sk.MaxMHz))
			models = append(models, sk.Name)
			caches = append(caches, fmt.Sprintf("%d KB", cache))
		}
		if sk.MaxMHz != sk.CurrentMHz && sk.MaxMHz > 0 {
			maxDiffers = true
		}
	}
	htt := "no"
	if cores > 0 && cores < virtual {
		htt = "yes"
	}
	w.nameVal("Processors", fmt.Sprintf("physical = %d, cores = %d, virtual = %d, hyperthreading = %s", physical, cores, virtual, htt))
	w.nameVal("Speeds", groupConcat(speeds))
	if maxDiffers {
		w.nameVal("Max Speeds", groupConcat(maxSpeeds))
	}
	w.nameVal("Models", groupConcat(models))
	w.nameVal("Caches", groupConcat(caches))
	if ci.PowerPlan != "" {
		w.nameVal("Power Plan", ci.PowerPlan)
	}

	if len(ci.Caches) > 0 {
		w.println("  Designation               Configuration                  Size     Associativity")
		w.println("  ========================= ============================== ======== ======================")
		for _, c := range ci.Caches {
			var conf []string
			if c.Level >= 3 && c.Level <= 5 {
				conf = append(conf, fmt.Sprintf("Level %d", c.Level-2))
			}
			if t, ok := cacheTypes[c.CacheType]; ok {
				conf = append(conf, t)
			}
			if p, ok := cacheWritePolicies[c.WritePolicy]; ok {
				conf = append(conf, p)
			}
			w.printf("  %-25s %-30s %-8s %s\n", truncate(c.Purpose, 25), strings.Join(conf, ", "),
				fmt.Sprintf("%d kB", c.InstalledKB), cacheAssociativity[c.Associativity])
		}
	}
}

// ---- memory -----------------------------------------------------------------

var memoryFormFactors = map[int]string{
	0: "Unknown", 1: "Other", 2: "SIP", 3: "DIP", 4: "ZIP", 5: "SOJ", 6: "Proprietary",
	7: "SIMM", 8: "DIMM", 9: "TSOP", 10: "PGA", 11: "RIMM", 12: "SODIMM", 13: "SRIMM",
	14: "SMD", 15: "SSMP", 16: "QFP", 17: "TQFP", 18: "SOIC", 19: "LCC", 20: "PLCC",
	21: "BGA", 22: "FPBGA", 23: "LGA",
}

var smbiosMemoryTypes = map[int]string{
	1: "Other", 2: "Unknown", 3: "DRAM", 4: "EDRAM", 5: "VRAM", 6: "SRAM", 7: "RAM",
	8: "ROM", 9: "Flash", 10: "EEPROM", 11: "FEPROM", 12: "EPROM", 13: "CDRAM", 14: "3DRAM",
	15: "SDRAM", 16: "SGRAM", 17: "RDRAM", 18: "DDR", 19: "DDR2", 20: "DDR2 FB-DIMM",
	24: "DDR3", 25: "FBD2", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2", 29: "LPDDR3",
	30: "LPDDR4", 31: "Logical non-volatile device", 32: "HBM", 33: "HBM2", 34: "DDR5",
	35: "LPDDR5", 36: "HBM3",
}

// Win32_PhysicalMemory.MemoryType, used when SMBIOSMemoryType is not set.
var legacyMemoryTypes = map[int]string{20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM", 24: "DDR3", 26: "DDR4"}

var memoryTypeDetails = []struct {
	bit  int
	name string
}{
	{0x2, "Other"}, {0x4, "Unknown"}, {0x8, "Fast-paged"}, {0x10, "Static column"},
	{0x20, "Pseudo-static"}, {0x40, "RAMBUS"}, {0x80, "Synchronous"}, {0x100, "CMOS"},
	{0x200, "EDO"}, {0x400, "Window DRAM"}, {0x800, "Cache DRAM"}, {0x1000, "Non-volatile"},
	{0x2000, "Registered (Buffered)"}, {0x4000, "Unbuffered (Unregistered)"}, {0x8000, "LRDIMM"},
}

func reportMemory(w *writer, s *Samples) {
	mi := s.Memory
	w.section("Memory")
	w.withNameValLen(14, func() {
		var swapAlloc, swapUsed uint64
		for _, p := range mi.Pagefiles {
			swapAlloc += p.AllocatedMB << 20
			swapUsed += p.CurrentUsedMB << 20
		}
		physical := uint64(0)
		if mi.TotalPhys > mi.AvailPhys {
			physical = mi.TotalPhys - mi.AvailPhys
		}
		w.nameVal("Total", shortenU(mi.TotalPhys, 1))
		w.nameVal("Free", shortenU(mi.FreeZero, 1))
		w.nameVal("Available", shortenU(mi.AvailPhys, 1))
		w.nameVal("Used", fmt.Sprintf("physical = %s, pagefile allocated = %s, pagefile used = %s, virtual = %s",
			shortenU(physical, 1), shortenU(swapAlloc, 1), shortenU(swapUsed, 1), shortenU(physical+swapUsed, 1)))
		w.nameVal("Commit", fmt.Sprintf("%s of %s limit (peak %s)",
			shortenU(mi.CommitTotal, 1), shortenU(mi.CommitLimit, 1), shortenU(mi.CommitPeak, 1)))
		w.nameVal("Caches", fmt.Sprintf("%s (standby list), system cache = %s", shortenU(mi.Standby, 1), shortenU(mi.CacheBytes, 1)))
		w.nameVal("Dirty", fmt.Sprintf("%s (modified page list)", shortenU(mi.Modified, 1)))
		w.nameVal("Kernel Pools", fmt.Sprintf("paged = %s, nonpaged = %s", shortenU(mi.PagedPool, 1), shortenU(mi.NonPaged, 1)))
		w.nameVal("UsedRSS", shortenU(mi.UsedRSS, 1))

		var pf []string
		for _, p := range mi.Pagefiles {
			pf = append(pf, fmt.Sprintf("%s %s (peak used %s)", p.Name, shortenU(p.AllocatedMB<<20, 1), shortenU(p.PeakUsedMB<<20, 1)))
		}
		pfs := strings.Join(pf, ", ")
		if pfs == "" {
			pfs = "none"
		}
		if mi.AutomaticPagefile {
			pfs += "; size managed by Windows"
		} else {
			var set []string
			for _, p := range mi.PagefileSettings {
				if p.InitialMB == 0 && p.MaximumMB == 0 {
					set = append(set, p.Name+" system managed")
				} else {
					set = append(set, fmt.Sprintf("%s initial %s, max %s", p.Name, shortenU(p.InitialMB<<20, 1), shortenU(p.MaximumMB<<20, 1)))
				}
			}
			if len(set) > 0 {
				pfs += "; configured: " + strings.Join(set, ", ")
			}
		}
		w.nameVal("Pagefile", pfs)

		if len(s.CPU.NUMA) > 0 {
			w.nameVal("Numa Nodes", strconv.Itoa(len(s.CPU.NUMA)))
		}
	})

	if len(s.CPU.NUMA) > 0 {
		w.println("   Node    Size        Free        CPUs")
		w.println("   ====    ====        ====        ====")
		for _, n := range s.CPU.NUMA {
			w.printf("   %-8s%-12s%-12s%s\n", fmt.Sprintf("node%d", n.Node),
				fmt.Sprintf("%d MB", n.TotalMB), fmt.Sprintf("%d MB", n.FreeMB), n.CPUs)
		}
		w.println("")
	}

	if len(mi.DIMMs) > 0 {
		dimms := append([]DIMM(nil), mi.DIMMs...)
		// Some firmwares reuse the same locator on every channel; add the
		// bank label to tell the modules apart.
		seen := map[string]int{}
		for _, d := range dimms {
			seen[d.Locator]++
		}
		for i, d := range dimms {
			if seen[d.Locator] > 1 && d.BankLabel != "" {
				dimms[i].Locator = d.BankLabel + " " + d.Locator
			}
		}
		sort.SliceStable(dimms, func(i, j int) bool { return dimms[i].Locator < dimms[j].Locator })
		lw := 9
		for _, d := range dimms {
			if l := len([]rune(d.Locator)); l > lw {
				lw = l
			}
		}
		w.printf("  %-*s %-8s %-17s %-13s %-13s %s\n", lw, "Locator", "Size", "Speed", "Form Factor", "Type", "Type Detail")
		w.printf("  %s ======== ================= ============= ============= ===========\n", strings.Repeat("=", lw))
		for _, d := range dimms {
			size := fmt.Sprintf("%d MB", d.Capacity>>20)
			if d.Capacity >= 1<<30 && d.Capacity%(1<<30) == 0 {
				size = fmt.Sprintf("%d GB", d.Capacity>>30)
			}
			speed := "Unknown"
			if d.ConfiguredSpeed > 0 {
				speed = fmt.Sprintf("%d MT/s", d.ConfiguredSpeed)
			} else if d.Speed > 0 {
				speed = fmt.Sprintf("%d MT/s", d.Speed)
			}
			typ, ok := smbiosMemoryTypes[d.SMBIOSMemoryType]
			if !ok || d.SMBIOSMemoryType <= 2 {
				if lt, ok := legacyMemoryTypes[d.MemoryType]; ok {
					typ = lt
				} else if typ == "" {
					typ = "Unknown"
				}
			}
			var details []string
			for _, td := range memoryTypeDetails {
				if d.TypeDetail&td.bit != 0 {
					details = append(details, td.name)
				}
			}
			w.printf("  %-*s %-8s %-17s %-13s %-13s %s\n", lw, d.Locator, size, speed,
				memoryFormFactors[d.FormFactor], typ, strings.Join(details, " "))
		}
		if mi.SlotsTotal > 0 {
			w.printf("  %d of %d memory slots populated", len(mi.DIMMs), mi.SlotsTotal)
			if mi.MaxCapacityKB > 0 {
				w.printf(", maximum capacity %s", shortenU(mi.MaxCapacityKB<<10, 1))
			}
			w.println("")
		}
	}
}

// ---- filesystems ------------------------------------------------------------

func reportMounts(w *writer, s *Samples) {
	var vols []Volume
	for _, v := range s.Storage.Volumes {
		// Skip unmounted volumes (\\?\Volume{...}\) and empty removable drives.
		if strings.HasPrefix(v.Name, `\\?\`) || v.Capacity == 0 {
			continue
		}
		vols = append(vols, v)
	}
	if len(vols) == 0 && s.Errors["storage"] == "" {
		return
	}
	w.section("Mounted Filesystems")
	if len(vols) == 0 {
		w.println("Unable to collect information")
	} else {
		sort.Slice(vols, func(i, j int) bool { return strings.ToLower(vols[i].Name) < strings.ToLower(vols[j].Name) })
		type row struct{ fs, size, used, typ, opts, mnt string }
		rows := make([]row, 0, len(vols))
		dw, tw, ow := 10, 4, 4
		for _, v := range vols {
			label := v.Label
			if label == "" {
				label = "-"
			}
			used := uint64(0)
			if v.Capacity > v.FreeSpace {
				used = v.Capacity - v.FreeSpace
			}
			pct := int(math.Ceil(float64(used) / float64(v.Capacity) * 100))
			opts := []string{"bs=" + shortenU(v.BlockSize, 0)}
			if v.Compressed {
				opts = append(opts, "compressed")
			}
			if v.Indexing {
				opts = append(opts, "indexed")
			}
			if v.BootVolume {
				opts = append(opts, "boot")
			}
			if v.SystemVolume {
				opts = append(opts, "system")
			}
			if v.PageFile {
				opts = append(opts, "pagefile")
			}
			r := row{label, shortenU(v.Capacity, 1), fmt.Sprintf("%d%%", pct), v.FileSystem, strings.Join(opts, ","), v.Name}
			if v.BlockSize == 0 {
				r.opts = strings.Join(opts[1:], ",")
			}
			if l := len([]rune(r.fs)); l > dw {
				dw = l
			}
			if len(r.typ) > tw {
				tw = len(r.typ)
			}
			if len(r.opts) > ow {
				ow = len(r.opts)
			}
			rows = append(rows, r)
		}
		spec := fmt.Sprintf("  %%-%ds %%7s %%4s %%-%ds %%-%ds %%s\n", dw, tw, ow)
		w.printf(spec, "Filesystem", "Size", "Used", "Type", "Opts", "Mountpoint")
		for _, r := range rows {
			w.printf(spec, r.fs, r.size, r.used, r.typ, r.opts, r.mnt)
		}
	}

	w.section("Filesystem Settings")
	w.nameVal("8dot3 Names", describe8dot3(s.Storage.FS.Disable8dot3))
	w.nameVal("Last Access", describeLastAccess(s.Storage.FS.DisableLastAccess))
}

func describe8dot3(v int64) string {
	switch v {
	case 0:
		return "created on all volumes"
	case 1:
		return "disabled on all volumes"
	case 2:
		return "set per volume"
	case 3:
		return "disabled on all volumes except the system volume"
	case -1:
		return "unknown"
	}
	return fmt.Sprintf("unknown value %d", v)
}

func describeLastAccess(v int64) string {
	if v < 0 {
		return "unknown"
	}
	state := "updates enabled"
	if v&1 == 1 {
		state = "updates disabled"
	}
	managed := "user managed"
	if v&0x80000000 != 0 && v&2 == 0 {
		managed = "system managed"
	}
	return fmt.Sprintf("%s, %s (0x%x)", state, managed, v)
}

// ---- disks ------------------------------------------------------------------

var mediaTypes = map[int]string{0: "Unspecified", 3: "HDD", 4: "SSD", 5: "SCM"}
var busTypes = map[int]string{
	0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 5: "SSA", 6: "Fibre Channel",
	7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC",
	14: "Virtual", 15: "File Backed Virtual", 16: "Storage Spaces", 17: "NVMe", 18: "SCM", 19: "UFS",
}
var healthStatuses = map[int]string{0: "Healthy", 1: "Warning", 2: "Unhealthy", 5: "Unknown"}
var partitionStyles = map[int]string{0: "RAW", 1: "MBR", 2: "GPT"}
var gptTypes = map[string]string{
	"c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
	"e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
	"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Basic Data",
	"de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Recovery",
	"5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "LDM Metadata",
	"af9b60a0-1431-4f62-bc68-3311714a69ad": "LDM Data",
	"e75caf8f-f680-4cee-afa3-b001e56efc2d": "Storage Spaces",
	"db97dba9-0840-4bae-97f0-ffb9a327c7e1": "Cluster Metadata",
}

func lookup(m map[int]string, k int) string {
	if v, ok := m[k]; ok {
		return v
	}
	return strconv.Itoa(k)
}

func reportDisks(w *writer, s *Samples) {
	st := s.Storage
	w.section("Physical Disks")
	if !st.SpacesAvailable {
		w.println("Unable to collect information")
	} else {
		pds := append([]PhysicalDisk(nil), st.PhysicalDisks...)
		sort.SliceStable(pds, func(i, j int) bool { return naturalLess(pds[i].DeviceID, pds[j].DeviceID) })
		for _, d := range pds {
			desc := []string{
				lookup(mediaTypes, d.MediaType) + " " + lookup(busTypes, d.BusType),
				shortenU(d.Size, 1),
				d.FriendlyName,
			}
			if d.Firmware != "" {
				desc = append(desc, "fw "+d.Firmware)
			}
			if d.LogicalSectorSize > 0 {
				desc = append(desc, fmt.Sprintf("sectors %d/%d", d.LogicalSectorSize, d.PhysicalSectorSize))
			}
			if d.SpindleSpeed > 0 && d.SpindleSpeed != 0xFFFFFFFF {
				desc = append(desc, fmt.Sprintf("%d rpm", d.SpindleSpeed))
			}
			desc = append(desc, lookup(healthStatuses, d.HealthStatus))
			w.nameVal("Disk "+d.DeviceID, strings.Join(desc, ", "))
		}
	}

	w.section("Disk Partitioning")
	if len(st.Disks) == 0 {
		if !st.SpacesAvailable {
			w.println("Unable to collect information")
		}
		return
	}
	const mib = 1 << 20
	format := "%-12s %4s %10s %10s %18s %5s %s\n"
	w.printf(format, "Device", "Type", "Start", "End", "Size", "Align", "Info")
	w.printf(format, "============", "====", "==========", "==========", "==================", "=====", "====")
	disks := append([]Disk(nil), st.Disks...)
	sort.Slice(disks, func(i, j int) bool { return disks[i].Number < disks[j].Number })
	for _, d := range disks {
		var info []string
		info = append(info, lookup(partitionStyles, d.PartitionStyle), lookup(busTypes, d.BusType))
		if d.IsBoot {
			info = append(info, "boot")
		}
		if d.IsSystem {
			info = append(info, "system")
		}
		if d.IsOffline {
			info = append(info, "OFFLINE")
		}
		if d.IsReadOnly {
			info = append(info, "read-only")
		}
		info = append(info, d.FriendlyName)
		w.printf(format, fmt.Sprintf("Disk %d", d.Number), "Disk", "", "", strconv.FormatUint(d.Size, 10), "", strings.Join(info, ", "))

		var parts []Partition
		for _, p := range st.Partitions {
			if p.DiskNumber == d.Number {
				parts = append(parts, p)
			}
		}
		sort.Slice(parts, func(i, j int) bool { return parts[i].Offset < parts[j].Offset })
		for _, p := range parts {
			var pinfo []string
			if p.DriveLetter != "" {
				pinfo = append(pinfo, p.DriveLetter+":")
			}
			for _, ap := range p.AccessPaths {
				if !strings.HasPrefix(ap, `\\?\`) && !(p.DriveLetter != "" && strings.EqualFold(ap, p.DriveLetter+`:\`)) {
					pinfo = append(pinfo, ap)
				}
			}
			if t, ok := gptTypes[p.GptType]; ok {
				pinfo = append(pinfo, t)
			} else if p.MbrType != 0 {
				pinfo = append(pinfo, fmt.Sprintf("MBR type 0x%02x", p.MbrType))
			}
			w.printf(format, fmt.Sprintf("Disk %d #%d", d.Number, p.PartitionNumber), "Part",
				strconv.FormatUint(p.Offset/mib, 10), strconv.FormatUint((p.Offset+p.Size)/mib, 10),
				strconv.FormatUint(p.Size, 10), alignment(p.Offset), strings.Join(pinfo, ", "))
		}
	}
	w.println("Start and End are in MiB. Size is in bytes.")
}

func alignment(off uint64) string {
	switch {
	case off%(1<<20) == 0:
		return "1M"
	case off%(64<<10) == 0:
		return "64K"
	case off%(4<<10) == 0:
		return "4K"
	}
	return "NO"
}

var digitsRe = regexp.MustCompile(`^\d+$`)

func naturalLess(a, b string) bool {
	if digitsRe.MatchString(a) && digitsRe.MatchString(b) {
		ai, _ := strconv.Atoi(a)
		bi, _ := strconv.Atoi(b)
		return ai < bi
	}
	return a < b
}

func reportKernelObjects(w *writer, s *Samples) {
	w.section("Kernel Object Counts")
	w.nameVal("handles", strconv.FormatUint(uint64(s.Memory.HandleCount), 10))
	w.nameVal("processes", strconv.FormatUint(uint64(s.Memory.ProcessCount), 10))
	w.nameVal("threads", strconv.FormatUint(uint64(s.Memory.ThreadCount), 10))
}

var provisioningTypes = map[int]string{0: "Unknown", 1: "Thin", 2: "Fixed"}

func reportStorageSpaces(w *writer, s *Samples) {
	st := s.Storage
	w.section("Storage Spaces Virtual Disks")
	switch {
	case !st.SpacesAvailable:
		w.println("Unable to collect information")
	case len(st.VirtualDisks) == 0:
		w.println("No virtual disks")
	default:
		format := "  %-24s %-10s %8s %9s %7s %6s %9s %8s %s\n"
		w.printf(format, "Name", "Resiliency", "Size", "Footprint", "Columns", "Copies", "Interleave", "Provision", "Health")
		for _, v := range st.VirtualDisks {
			w.printf(format, truncate(v.FriendlyName, 24), v.Resiliency, shortenU(v.Size, 1), shortenU(v.FootprintOnPool, 1),
				strconv.Itoa(v.NumberOfColumns), strconv.Itoa(v.DataCopies), shortenU(v.Interleave, 0),
				lookup(provisioningTypes, v.ProvisioningType), lookup(healthStatuses, v.HealthStatus))
		}
	}
	w.section("Storage Spaces Pools")
	switch {
	case !st.SpacesAvailable:
		w.println("Unable to collect information")
	case len(st.Pools) == 0:
		w.println("No storage pools")
	default:
		format := "  %-24s %8s %9s %s\n"
		w.printf(format, "Name", "Size", "Allocated", "Health")
		for _, p := range st.Pools {
			w.printf(format, truncate(p.FriendlyName, 24), shortenU(p.Size, 1), shortenU(p.AllocatedSize, 1), lookup(healthStatuses, p.HealthStatus))
		}
	}
}

// ---- RAID -------------------------------------------------------------------

const (
	raidMegaRAID = "megaraid"
	raidMegaCLI  = "megacli"
	raidHP       = "hp"
	raidAdaptec  = "adaptec"
	raidIntel    = "intel"
	raidLSIHBA   = "lsihba"
)

var raidNames = map[string]string{
	raidMegaRAID: "LSI Logic MegaRAID SAS",
	raidHP:       "HP Smart Array",
	raidAdaptec:  "AACRAID",
	raidIntel:    "Intel RST/VROC",
	raidLSIHBA:   "Fusion-MPT SAS",
}

var (
	reMegaRAID = regexp.MustCompile(`(?i)megaraid|\bperc\b|megasas|avago.*raid|broadcom.*raid|lsi.*raid`)
	reHP       = regexp.MustCompile(`(?i)smart ?array|hpsa|hpe.*\bsr\d|hpcisss`)
	reAdaptec  = regexp.MustCompile(`(?i)adaptec|microsemi|microchip.*smart|smartraid|smarthba|arcsas|\baac`)
	reIntel    = regexp.MustCompile(`(?i)\biastor|intel.*\b(rst|raid|vroc)\b|\bvroc`)
	reLSIHBA   = regexp.MustCompile(`(?i)\blsi_sas|\blsi adapter|sas\d? \d{4}|avago adapter|broadcom adapter|fusion-?mpt`)
)

func raidKind(c StorageController) string {
	s := c.Name + " " + c.Manufacturer + " " + c.DriverName
	switch {
	case reMegaRAID.MatchString(s):
		return raidMegaRAID
	case reHP.MatchString(s):
		return raidHP
	case reAdaptec.MatchString(s):
		return raidAdaptec
	case reIntel.MatchString(s):
		return raidIntel
	case reLSIHBA.MatchString(s):
		return raidLSIHBA
	}
	return ""
}

func reportRAID(w *writer, s *Samples) {
	w.section("RAID Controller")
	controller := "No RAID controller detected"
	for _, c := range s.RAID.Controllers {
		if k := raidKind(c); k != "" {
			controller = raidNames[k]
			break
		}
	}
	w.nameVal("Controller", controller)
	for _, c := range s.RAID.Controllers {
		desc := c.Name
		if c.DriverName != "" {
			desc += " (driver " + c.DriverName + ")"
		}
		if c.Status != "" && c.Status != "OK" {
			desc += ", status " + c.Status
		}
		w.nameVal("Adapter", desc)
	}
	for _, t := range s.RAID.VendorTools {
		w.printf("  Output of %s:\n", t.Command)
		if t.Output != "" {
			w.println(t.Output)
		}
		if t.Error != "" {
			w.printf("  (%s: %s)\n", t.Tool, t.Error)
		}
	}
}

// ---- network ----------------------------------------------------------------

func formatSpeed(bps uint64) string {
	switch {
	case bps == 0:
		return "Unknown"
	case bps >= 1e9 && bps%1e9 == 0:
		return fmt.Sprintf("%dGb/s", bps/1e9)
	case bps >= 1e9:
		return fmt.Sprintf("%.1fGb/s", float64(bps)/1e9)
	default:
		return fmt.Sprintf("%dMb/s", bps/1e6)
	}
}

func reportNetwork(w *writer, s *Samples) {
	ni := s.Network
	w.section("Network Config")
	for _, a := range ni.Adapters {
		if a.HardwareInterface && !a.Virtual {
			w.nameVal("Controller", a.Description)
		}
	}
	tw := "120 (default)"
	if ni.TCP.TimedWaitDelay >= 0 {
		tw = strconv.Itoa(ni.TCP.TimedWaitDelay)
	}
	w.nameVal("TIME_WAIT", tw)
	if ni.TCP.DynamicPortCount > 0 {
		w.nameVal("Port Range", fmt.Sprintf("%d-%d (%d ports)", ni.TCP.DynamicPortStart,
			ni.TCP.DynamicPortStart+ni.TCP.DynamicPortCount-1, ni.TCP.DynamicPortCount))
	}
	if ni.TCP.MaxUserPort >= 0 {
		w.nameVal("MaxUserPort", strconv.Itoa(ni.TCP.MaxUserPort))
	}
	if ni.TCP.CongestionControl != "" {
		w.nameVal("Congestion", ni.TCP.CongestionControl)
	}
	if ni.TCP.AutoTuningLevel != "" {
		w.nameVal("Auto-Tuning", ni.TCP.AutoTuningLevel)
	}

	if len(ni.Stats) > 0 {
		w.section("Interface Statistics")
		stats := append([]NetStats(nil), ni.Stats...)
		sort.Slice(stats, func(i, j int) bool { return stats[i].Name < stats[j].Name })
		nw := 9
		for _, st := range stats {
			if l := len([]rune(st.Name)); l > nw {
				nw = l
			}
		}
		// Same columns as pt-summary, but wide enough for the large counters
		// of long running Windows servers.
		rows := make([][6]string, len(stats))
		vw := 10
		for i, st := range stats {
			for j, v := range []uint64{st.RxBytes, st.RxPackets, st.RxErrors, st.TxBytes, st.TxPackets, st.TxErrors} {
				rows[i][j] = strconv.FormatInt(fuzz(float64(v)), 10)
				if len(rows[i][j]) > vw {
					vw = len(rows[i][j])
				}
			}
		}
		line := "  %-*s %*s %*s %*s %*s %*s %*s\n"
		w.printf(line, nw, "interface", vw, "rx_bytes", vw, "rx_packets", vw, "rx_errors", vw, "tx_bytes", vw, "tx_packets", vw, "tx_errors")
		eq := strings.Repeat("=", vw)
		w.printf(line, nw, strings.Repeat("=", nw), vw, eq, vw, eq, vw, eq, vw, eq, vw, eq, vw, eq)
		for i, st := range stats {
			r := rows[i]
			w.printf(line, nw, st.Name, vw, r[0], vw, r[1], vw, r[2], vw, r[3], vw, r[4], vw, r[5])
		}
	}

	if len(ni.Adapters) > 0 {
		w.section("Network Devices")
		adapters := append([]NetAdapter(nil), ni.Adapters...)
		sort.Slice(adapters, func(i, j int) bool { return adapters[i].Name < adapters[j].Name })
		nw := 9
		for _, a := range adapters {
			if l := len([]rune(a.Name)); l > nw {
				nw = l
			}
		}
		format := "  %-*s %-10s %-6s %-12s %5s %-17s %s\n"
		w.printf(format, nw, "Device", "Speed", "Duplex", "Status", "MTU", "MAC", "Description")
		w.printf(format, nw, strings.Repeat("=", nw), "==========", "======", "============", "=====", "=================", "===========")
		for _, a := range adapters {
			duplex := "half"
			if a.FullDuplex {
				duplex = "full"
			}
			desc := a.Description
			if a.Virtual || !a.HardwareInterface {
				desc += " [virtual]"
			}
			w.printf(format, nw, a.Name, formatSpeed(a.SpeedBps), duplex, a.Status, strconv.Itoa(int(a.MTU)), a.MAC, desc)
		}
	}

	reportConnections(w, ni)
}

type countPair struct {
	key   string
	count int
}

func countBy(items []string) []countPair {
	m := map[string]int{}
	for _, i := range items {
		m[i]++
	}
	out := make([]countPair, 0, len(m))
	for k, v := range m {
		out = append(out, countPair{k, v})
	}
	return out
}

func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	a4, b4 := ia.To4(), ib.To4()
	if (a4 == nil) != (b4 == nil) {
		return a4 != nil // IPv4 first
	}
	if a4 != nil {
		ia, ib = a4, b4
	}
	return string(ia) < string(ib)
}

func isUnspecified(ip string) bool {
	p := net.ParseIP(ip)
	return p == nil || p.IsUnspecified()
}

func reportConnections(w *writer, ni NetworkInfo) {
	if ni.Connections == nil {
		return
	}
	w.section("Network Connections")
	var remotes, locals, ports, states []string
	listen := map[uint16]map[string]bool{}
	for _, c := range ni.Connections {
		states = append(states, c.State)
		if c.State == "LISTEN" {
			if listen[c.LocalPort] == nil {
				listen[c.LocalPort] = map[string]bool{}
			}
			name := ni.ProcessNames[c.PID]
			if name == "" {
				name = fmt.Sprintf("pid %d", c.PID)
			}
			listen[c.LocalPort][name] = true
			continue
		}
		if isUnspecified(c.RemoteAddr) || c.RemotePort == 0 {
			continue
		}
		remotes = append(remotes, c.RemoteAddr)
		locals = append(locals, c.LocalAddr)
		ports = append(ports, strconv.Itoa(int(c.LocalPort)))
	}

	printCounts := func(pairs []countPair) {
		for _, p := range pairs {
			w.printf("    %-15s %5d\n", p.key, fuzz(float64(p.count)))
		}
	}

	w.println("  Connections from remote IP addresses")
	rc := countBy(remotes)
	sort.Slice(rc, func(i, j int) bool { return ipLess(rc[i].key, rc[j].key) })
	printCounts(rc)

	w.println("  Connections to local IP addresses")
	lc := countBy(locals)
	sort.Slice(lc, func(i, j int) bool { return ipLess(lc[i].key, lc[j].key) })
	printCounts(lc)

	w.println("  Connections to top 10 local ports")
	pc := countBy(ports)
	sort.Slice(pc, func(i, j int) bool {
		if pc[i].count != pc[j].count {
			return pc[i].count > pc[j].count
		}
		return pc[i].key < pc[j].key
	})
	if len(pc) > 10 {
		pc = pc[:10]
	}
	sort.Slice(pc, func(i, j int) bool { return pc[i].key < pc[j].key })
	printCounts(pc)

	w.println("  States of connections")
	sc := countBy(states)
	sort.Slice(sc, func(i, j int) bool { return sc[i].key < sc[j].key })
	printCounts(sc)

	w.println("  Listening ports")
	lp := make([]int, 0, len(listen))
	for p := range listen {
		lp = append(lp, int(p))
	}
	sort.Ints(lp)
	for _, p := range lp {
		var names []string
		for n := range listen[uint16(p)] {
			names = append(names, n)
		}
		sort.Strings(names)
		w.printf("    %-15d %s\n", p, strings.Join(names, ", "))
	}
}

// ---- processes --------------------------------------------------------------

func cpuTime(sec float64) string {
	total := int64(sec * 100)
	return fmt.Sprintf("%d:%02d.%02d", total/6000, (total/100)%60, total%100)
}

func writeProcessTable(w *writer, procs []Process, totalPhys uint64) {
	w.printf("%7s %-24s %3s %5s %6s %7s %7s %6s %5s %10s %s\n",
		"PID", "USER", "PR", "THR", "HND", "RES", "PRIV", "%CPU", "%MEM", "TIME+", "COMMAND")
	for _, p := range procs {
		user := p.User
		if user == "" {
			user = "?"
		}
		mem := 0.0
		if totalPhys > 0 {
			mem = float64(p.WorkingSet) / float64(totalPhys) * 100
		}
		w.printf("%7d %-24s %3d %5d %6d %7s %7s %6.1f %5.1f %10s %s\n",
			p.PID, truncate(user, 24), p.Priority, p.Threads, p.Handles,
			shortenU(p.WorkingSet, 1), shortenU(p.Private, 1), p.CPUPercent, mem, cpuTime(p.CPUSeconds), p.Name)
	}
}

var (
	reDBService = regexp.MustCompile(`(?i)mysql|mariadb|percona|postgres|pg_ctl|pgbouncer|patroni|mongo|proxysql|haproxy|` +
		`sqlservr|mssql|redis|valkey|memcache|pmm-agent|node_exporter|orchestrator|xtrabackup|etcd`)
	reSecurityService = regexp.MustCompile(`(?i)^(windefend|sense|mdcoresvc|wdnissvc)$|msmpeng|mssense|csfalcon|sentinel|` +
		`symantec|ccsvchst|mcafee|mcshield|masvc|sophos|savservice|ekrn|eset|kaspersky|\bavp\b|carbonblack|cbdefense|` +
		`repmgr|cylance|cyserver|cortex|traps|tmccsf|ntrtscan|trend ?micro|elastic-(agent|endpoint)|wazuh|ossec|bitdefender|` +
		`epsecurityservice|cisco ?amp|sfc\.exe|qualys|rapid7|tanium|crowdstrike`)
)

func reportProcesses(w *writer, s *Samples) {
	pi := s.Processes
	w.section("Top Processes")
	if len(pi.Top) == 0 {
		w.println("Unable to collect information")
	} else {
		writeProcessTable(w, pi.Top, pi.TotalPhys)
		w.printf("  %%CPU is measured over %.0f seconds; 100%% = one logical CPU (%d logical CPUs).\n", pi.SampleSeconds, pi.LogicalCPUs)
	}

	if len(pi.TopMem) > 0 {
		w.section("Top Processes By Memory")
		writeProcessTable(w, pi.TopMem, pi.TotalPhys)
	}

	w.section("Notable Processes")
	format := "%7s  %-8s %-9s %-4s %s\n"
	w.printf(format, "PID", "STATE", "START", "KIND", "SERVICE")
	var sshd *Service
	for i := range pi.Services {
		if strings.EqualFold(pi.Services[i].Name, "sshd") {
			sshd = &pi.Services[i]
		}
	}
	if sshd != nil && strings.EqualFold(sshd.State, "Running") {
		w.printf(format, strconv.Itoa(int(sshd.PID)), sshd.State, sshd.StartMode, "ssh", "sshd")
	} else {
		w.printf("%7s  %s\n", "?", "sshd doesn't appear to be running")
	}
	for _, sv := range pi.Services {
		// Match on the service name and executable name only: display names
		// are localized and too generic (e.g. "Update Orchestrator Service").
		match := sv.Name + " " + filepath.Base(strings.ReplaceAll(sv.Image, `\`, "/"))
		kind := ""
		switch {
		case reDBService.MatchString(match):
			kind = "db"
		case reSecurityService.MatchString(match):
			kind = "sec"
		default:
			continue
		}
		pid := "-"
		if sv.PID != 0 {
			pid = strconv.Itoa(int(sv.PID))
		}
		desc := sv.Name
		if sv.DisplayName != "" && sv.DisplayName != sv.Name {
			desc += " (" + sv.DisplayName + ")"
		}
		if sv.Image != "" {
			desc += " " + sv.Image
		}
		w.printf(format, pid, sv.State, sv.StartMode, kind, desc)
	}

	w.section("Simplified and fuzzy rounded vmstat (wait please)")
	if len(s.Vmstat) == 0 {
		w.println("Unable to collect information")
		return
	}
	vf := "  %2s %2s  %4s %4s %7s %7s %7s %7s %3s %3s %3s %3s\n"
	w.println("  procs  ---page-- -------io------ -----system---- -----cpu-------")
	w.printf(vf, "r", "dq", "pi", "po", "bi", "bo", "in", "cs", "us", "sy", "id", "hi")
	f := func(v float64) string { return strconv.FormatInt(fuzz(v), 10) }
	pct := func(v float64) string { return strconv.Itoa(int(math.Round(v))) }
	for _, v := range s.Vmstat {
		w.printf(vf, f(v.ProcQueue), f(v.DiskQueue), f(v.PagesIn), f(v.PagesOut), f(v.ReadKB), f(v.WriteKB),
			f(v.Interrupts), f(v.CtxSwitches), pct(v.User), pct(v.Privileged), pct(v.Idle), pct(v.InterruptTime))
	}
}

// ---- memory management, security, errors -----------------------------------

func reportMemoryMgmt(w *writer, s *Samples) {
	mm := s.MemoryMgmt
	w.section("Memory management")
	if mm.LargePageMinimum > 0 {
		w.printf("Large pages are supported, the large page size is %s.\n", shortenU(mm.LargePageMinimum, 1))
	} else {
		w.println("Large pages are not supported on this system.")
	}
	switch {
	case mm.LockPagesError != "":
		w.printf("Lock pages in memory (SeLockMemoryPrivilege) holders: unknown (%s).\n", mm.LockPagesError)
	case len(mm.LockPagesHolders) == 0:
		w.println("Lock pages in memory (SeLockMemoryPrivilege) is not granted to any account.")
	default:
		w.printf("Lock pages in memory (SeLockMemoryPrivilege) is granted to: %s.\n", strings.Join(mm.LockPagesHolders, ", "))
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func reportSecurity(w *writer, s *Samples) {
	sec := s.Security
	w.section("Security")
	if sec.DefenderPresent {
		mode := ""
		if sec.DefenderRunningMode != "" {
			mode = ", mode " + sec.DefenderRunningMode
		}
		w.nameVal("Defender", fmt.Sprintf("antivirus %s, real-time protection %s%s",
			onOff(sec.DefenderAVEnabled), onOff(sec.DefenderRealTime), mode))
		switch {
		case sec.ExclusionsNote != "":
			w.nameVal("Exclusions", "unknown ("+sec.ExclusionsNote+")")
		case len(sec.ExclusionPaths) == 0 && len(sec.ExclusionProcesses) == 0:
			w.nameVal("Exclusions", "none")
		default:
			if len(sec.ExclusionPaths) > 0 {
				w.nameVal("Exclusions", "paths: "+strings.Join(sec.ExclusionPaths, "; "))
			}
			if len(sec.ExclusionProcesses) > 0 {
				w.nameVal("Exclusions", "processes: "+strings.Join(sec.ExclusionProcesses, "; "))
			}
		}
	} else {
		w.nameVal("Defender", "not detected")
	}
	if len(sec.Firewall) > 0 {
		var fw []string
		for _, p := range sec.Firewall {
			state := "on"
			switch p.Enabled {
			case 0:
				state = "off"
			case 2:
				state = "not configured"
			}
			fw = append(fw, p.Name+" = "+state)
		}
		w.nameVal("Firewall", strings.Join(fw, ", "))
	}
}

func reportErrors(w *writer, s *Samples) {
	if len(s.Errors) == 0 {
		return
	}
	w.section("Collection Errors")
	for _, k := range sortedKeys(s.Errors) {
		w.printf("  %s: %s\n", k, s.Errors[k])
	}
}
