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

// Data collection on Windows.
//
// Sources, in order of preference:
//   - WMI/CIM classes (language independent: we only read numeric codes and
//     names, never parse localized text),
//   - Win32 APIs,
//   - the registry,
//   - PDH performance counters, added by their English names so they work on
//     every display language.
//
// Nothing here parses the output of command line tools such as systeminfo,
// netsh or wmic, whose output is localized and/or no longer shipped.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func collectAll(s *Samples, timeout time.Duration) error {
	s.System = run(s, "system", timeout, collectSystem)
	s.TimeZoneName = regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, "TimeZoneKeyName")
	hf := run(s, "hotfixes", timeout, collectHotfixes)
	s.System.HotfixCount = hf.count
	s.System.LastHotfixID = hf.lastID
	s.System.LastHotfixInstalled = hf.lastDate

	s.CPU = run(s, "cpu", timeout, collectCPU)
	s.Memory = run(s, "memory", timeout, collectMemory)
	s.Storage = run(s, "storage", timeout, func() (StorageInfo, error) {
		return collectStorage(s.Options.SummarizeMounts)
	})
	s.RAID = run(s, "raid", timeout, collectRAID)

	if s.Options.SummarizeNetwork {
		s.Network = run(s, "network", timeout, collectNetwork)
	}
	if s.Options.SummarizeProcesses {
		s.Processes.Services = run(s, "services", timeout, collectServices)
	}
	s.MemoryMgmt = run(s, "memory_management", timeout, collectMemoryMgmt)
	s.Security = run(s, "security", timeout, collectSecurity)

	// The sampling window (vmstat + per process CPU usage) runs last, after
	// all other collectors are done, so our own WMI activity doesn't distort
	// the numbers.
	if s.Options.SummarizeProcesses {
		type sampling struct {
			vm   []VmstatSample
			proc ProcessInfo
		}
		sleep := time.Duration(s.Options.Sleep) * time.Second
		res := run(s, "sampling", timeout+sleep, func() (sampling, error) {
			vm, proc, err := collectSampling(s.Options.Sleep)
			return sampling{vm, proc}, err
		})
		s.Vmstat = res.vm
		services := s.Processes.Services
		s.Processes = res.proc
		s.Processes.Services = services
		s.Processes.TotalPhys = s.Memory.TotalPhys
	}
	return nil
}

// ---- system -----------------------------------------------------------------

func first(rows []wmiRow) wmiRow {
	if len(rows) == 0 {
		return wmiRow{}
	}
	return rows[0]
}

func regString(k registry.Key, path, name string) string {
	key, err := registry.OpenKey(k, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	v, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// regInt returns -1 when the value doesn't exist.
func regInt(k registry.Key, path, name string) int64 {
	key, err := registry.OpenKey(k, path, registry.QUERY_VALUE)
	if err != nil {
		return -1
	}
	defer key.Close()
	v, _, err := key.GetIntegerValue(name)
	if err != nil {
		return -1
	}
	return int64(v)
}

func regKeyExists(k registry.Key, path string) bool {
	key, err := registry.OpenKey(k, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	key.Close()
	return true
}

func collectSystem() (SystemInfo, error) {
	var errs []error
	si := SystemInfo{}
	si.Elevated = windows.GetCurrentProcessToken().IsElevated()

	cs, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_ComputerSystem")
	errs = append(errs, err)
	c := first(cs)
	si.Hostname = c.str("DNSHostName")
	if si.Hostname == "" {
		si.Hostname = c.str("Name")
	}
	if si.Hostname == "" {
		si.Hostname, _ = os.Hostname()
	}
	si.Domain = c.str("Domain")
	si.PartOfDomain = c.b("PartOfDomain")
	si.DomainRole = c.i("DomainRole")
	si.Manufacturer = c.str("Manufacturer")
	si.Model = c.str("Model")
	si.HypervisorPresent = c.b("HypervisorPresent")

	osr, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_OperatingSystem")
	errs = append(errs, err)
	o := first(osr)
	si.OSCaption = o.str("Caption")
	si.OSVersion = o.str("Version")
	si.BuildNumber = o.str("BuildNumber")
	si.ProductType = o.i("ProductType")
	si.InstallDate = o.t("InstallDate")
	si.LastBoot = o.t("LastBootUpTime")

	if prod, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_ComputerSystemProduct"); err == nil {
		si.ProductVersion = first(prod).str("Version")
		if si.SerialNumber == "" {
			si.SerialNumber = first(prod).str("IdentifyingNumber")
		}
	}
	if bios, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_BIOS"); err == nil {
		b := first(bios)
		si.BIOSVendor = b.str("Manufacturer")
		si.BIOSVersion = b.str("SMBIOSBIOSVersion")
		if t := b.t("ReleaseDate"); !t.IsZero() {
			si.BIOSReleaseDate = t.Format("2006-01-02")
		}
		if sn := b.str("SerialNumber"); sn != "" {
			si.SerialNumber = sn
		}
	} else {
		errs = append(errs, err)
	}
	if enc, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_SystemEnclosure"); err == nil {
		e := first(enc)
		si.ChassisTypes = e.ints("ChassisTypes")
		si.ChassisAssetTag = e.str("SMBIOSAssetTag")
	}

	const cv = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	si.DisplayVersion = regString(registry.LOCAL_MACHINE, cv, "DisplayVersion")
	if si.DisplayVersion == "" {
		si.DisplayVersion = regString(registry.LOCAL_MACHINE, cv, "ReleaseId")
	}
	if ubr := regInt(registry.LOCAL_MACHINE, cv, "UBR"); ubr >= 0 {
		si.UBR = uint32(ubr)
	}
	si.EditionID = regString(registry.LOCAL_MACHINE, cv, "EditionID")
	si.InstallationType = regString(registry.LOCAL_MACHINE, cv, "InstallationType")
	si.NativeArch = regString(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "PROCESSOR_ARCHITECTURE")

	const w32 = `SYSTEM\CurrentControlSet\Services\W32Time\Parameters`
	si.TimeSyncType = regString(registry.LOCAL_MACHINE, w32, "Type")
	si.TimeSyncServer = regString(registry.LOCAL_MACHINE, w32, "NtpServer")

	si.PendingReboot = pendingReboot()
	return si, joinErrs(errs)
}

func pendingReboot() []string {
	reasons := []string{}
	if regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		reasons = append(reasons, "component servicing")
	}
	if regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		reasons = append(reasons, "Windows Update")
	}
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE); err == nil {
		if v, _, err := key.GetStringsValue("PendingFileRenameOperations"); err == nil && len(v) > 0 {
			reasons = append(reasons, "file rename operations")
		}
		key.Close()
	}
	return reasons
}

type hotfixes struct {
	count    int
	lastID   string
	lastDate string
}

// collectHotfixes reads Win32_QuickFixEngineering. InstalledOn is a string
// whose format is not consistent across Windows versions, so several formats
// are tried.
func collectHotfixes() (hotfixes, error) {
	rows, err := wmiQuery(nsCIMV2, "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering")
	if err != nil {
		return hotfixes{}, err
	}
	h := hotfixes{count: len(rows)}
	var last time.Time
	for _, r := range rows {
		t, ok := parseHotfixDate(r.str("InstalledOn"))
		if ok && !t.Before(last) {
			last = t
			h.lastID = r.str("HotFixID")
		}
	}
	if !last.IsZero() {
		h.lastDate = last.Format("2006-01-02")
	}
	return h, nil
}

func parseHotfixDate(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"1/2/2006", "01/02/2006", "2006-01-02", "20060102", "2.1.2006", "02.01.2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	// Some systems report a hexadecimal FILETIME.
	if n, err := strconv.ParseUint(s, 16, 64); err == nil && n > 0 {
		ft := windows.Filetime{LowDateTime: uint32(n), HighDateTime: uint32(n >> 32)}
		return time.Unix(0, ft.Nanoseconds()).UTC(), true
	}
	return time.Time{}, false
}

// ---- processor --------------------------------------------------------------

var knownPowerPlans = map[string]string{
	"381b4222-f694-41f0-9685-ff5bb260df2e": "Balanced",
	"8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": "High performance",
	"a1841308-3541-4fab-bc81-f71556f20b4a": "Power saver",
	"e9a42b02-d5df-448d-aa00-03f14749eb61": "Ultimate Performance",
}

func collectCPU() (CPUInfo, error) {
	var errs []error
	ci := CPUInfo{}

	rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_Processor")
	errs = append(errs, err)
	for _, r := range rows {
		ci.Sockets = append(ci.Sockets, CPUSocket{
			Name:              strings.Join(strings.Fields(r.str("Name")), " "),
			Manufacturer:      r.str("Manufacturer"),
			SocketDesignation: r.str("SocketDesignation"),
			Cores:             r.i("NumberOfCores"),
			Logical:           r.i("NumberOfLogicalProcessors"),
			CurrentMHz:        r.i("CurrentClockSpeed"),
			MaxMHz:            r.i("MaxClockSpeed"),
			L2KB:              r.i("L2CacheSize"),
			L3KB:              r.i("L3CacheSize"),
			Architecture:      r.i("Architecture"),
			DataWidth:         r.i("DataWidth"),
			AddressWidth:      r.i("AddressWidth"),
		})
	}

	if rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_CacheMemory"); err == nil {
		for _, r := range rows {
			ci.Caches = append(ci.Caches, CPUCache{
				Purpose:       r.str("Purpose"),
				Level:         r.i("Level"),
				InstalledKB:   r.u64("InstalledSize"),
				Associativity: r.i("Associativity"),
				CacheType:     r.i("CacheType"),
				WritePolicy:   r.i("WritePolicy"),
				Location:      r.i("Location"),
			})
		}
	}

	if rows, err := wmiQuery(nsPower, "SELECT ElementName, InstanceID FROM Win32_PowerPlan WHERE IsActive = TRUE"); err == nil && len(rows) > 0 {
		ci.PowerPlan = rows[0].str("ElementName")
	}
	if ci.PowerPlan == "" {
		guid := strings.ToLower(regString(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes`, "ActivePowerScheme"))
		if name, ok := knownPowerPlans[guid]; ok {
			ci.PowerPlan = name
		} else if guid != "" {
			ci.PowerPlan = "custom plan " + guid
		}
	}

	cpus, err := numaNodeCPUs()
	errs = append(errs, err)
	mem := map[int]wmiRow{}
	if rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_PerfRawData_PerfOS_NUMANodeMemory"); err == nil {
		for _, r := range rows {
			if n, err := strconv.Atoi(r.str("Name")); err == nil {
				mem[n] = r
			}
		}
	}
	nodes := make([]int, 0, len(cpus))
	for n := range cpus {
		nodes = append(nodes, n)
	}
	sort.Ints(nodes)
	for _, n := range nodes {
		r := mem[n]
		if r == nil {
			r = wmiRow{}
		}
		ci.NUMA = append(ci.NUMA, NUMANode{
			Node:        n,
			TotalMB:     r.u64("TotalMBytes"),
			FreeMB:      r.u64("FreeAndZeroPageListMBytes"),
			AvailableMB: r.u64("AvailableMBytes"),
			CPUs:        cpus[n],
		})
	}
	return ci, joinErrs(errs)
}

// ---- memory -----------------------------------------------------------------

func collectMemory() (MemoryInfo, error) {
	var errs []error
	mi := MemoryInfo{}

	if ms, err := globalMemoryStatus(); err == nil {
		mi.TotalPhys = ms.TotalPhys
		mi.AvailPhys = ms.AvailPhys
	} else {
		errs = append(errs, err)
	}
	if pi, err := getPerformanceInfo(); err == nil {
		ps := uint64(pi.PageSize)
		mi.CommitTotal = uint64(pi.CommitTotal) * ps
		mi.CommitLimit = uint64(pi.CommitLimit) * ps
		mi.CommitPeak = uint64(pi.CommitPeak) * ps
		mi.PagedPool = uint64(pi.KernelPaged) * ps
		mi.NonPaged = uint64(pi.KernelNonpaged) * ps
		mi.CacheBytes = uint64(pi.SystemCache) * ps
		mi.HandleCount = pi.HandleCount
		mi.ProcessCount = pi.ProcessCount
		mi.ThreadCount = pi.ThreadCount
	} else {
		errs = append(errs, err)
	}

	if rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_PerfRawData_PerfOS_Memory"); err == nil {
		r := first(rows)
		mi.FreeZero = r.u64("FreeAndZeroPageListBytes")
		mi.Standby = r.u64("StandbyCacheCoreBytes") + r.u64("StandbyCacheNormalPriorityBytes") + r.u64("StandbyCacheReserveBytes")
		mi.Modified = r.u64("ModifiedPageListBytes")
	} else {
		errs = append(errs, fmt.Errorf("memory performance counters: %w", err))
	}

	if rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_PageFileUsage"); err == nil {
		for _, r := range rows {
			mi.Pagefiles = append(mi.Pagefiles, Pagefile{
				Name:          r.str("Name"),
				AllocatedMB:   r.u64("AllocatedBaseSize"),
				CurrentUsedMB: r.u64("CurrentUsage"),
				PeakUsedMB:    r.u64("PeakUsage"),
			})
		}
	}
	if rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_PageFileSetting"); err == nil {
		for _, r := range rows {
			mi.PagefileSettings = append(mi.PagefileSettings, PagefileSetting{
				Name:      r.str("Name"),
				InitialMB: r.u64("InitialSize"),
				MaximumMB: r.u64("MaximumSize"),
			})
		}
	}
	if rows, err := wmiQuery(nsCIMV2, "SELECT AutomaticManagedPagefile FROM Win32_ComputerSystem"); err == nil {
		mi.AutomaticPagefile = first(rows).b("AutomaticManagedPagefile")
	}

	if rows, err := wmiQuery(nsCIMV2, "SELECT WorkingSetSize FROM Win32_Process"); err == nil {
		for _, r := range rows {
			mi.UsedRSS += r.u64("WorkingSetSize")
		}
	} else {
		errs = append(errs, err)
	}

	if rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_PhysicalMemory"); err == nil {
		for _, r := range rows {
			mi.DIMMs = append(mi.DIMMs, DIMM{
				Locator:          r.str("DeviceLocator"),
				BankLabel:        r.str("BankLabel"),
				Capacity:         r.u64("Capacity"),
				Speed:            r.i("Speed"),
				ConfiguredSpeed:  r.i("ConfiguredClockSpeed"),
				FormFactor:       r.i("FormFactor"),
				SMBIOSMemoryType: r.i("SMBIOSMemoryType"),
				MemoryType:       r.i("MemoryType"),
				TypeDetail:       r.i("TypeDetail"),
				Manufacturer:     r.str("Manufacturer"),
				PartNumber:       r.str("PartNumber"),
			})
		}
	}
	if rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_PhysicalMemoryArray"); err == nil {
		for _, r := range rows {
			// Use 3 = system memory. Some firmwares leave it unset.
			if u := r.i("Use"); u != 0 && u != 3 {
				continue
			}
			mi.SlotsTotal += r.i("MemoryDevices")
			mc := r.u64("MaxCapacityEx")
			if mc == 0 {
				mc = r.u64("MaxCapacity")
			}
			mi.MaxCapacityKB += mc
		}
	}
	return mi, joinErrs(errs)
}

// ---- storage ----------------------------------------------------------------

func collectStorage(mounts bool) (StorageInfo, error) {
	var errs []error
	st := StorageInfo{}

	if mounts {
		rows, err := wmiQuery(nsCIMV2, "SELECT * FROM Win32_Volume")
		errs = append(errs, err)
		for _, r := range rows {
			st.Volumes = append(st.Volumes, Volume{
				Name:         r.str("Name"),
				Label:        r.str("Label"),
				DriveLetter:  r.str("DriveLetter"),
				FileSystem:   r.str("FileSystem"),
				DriveType:    r.i("DriveType"),
				Capacity:     r.u64("Capacity"),
				FreeSpace:    r.u64("FreeSpace"),
				BlockSize:    r.u64("BlockSize"),
				Compressed:   r.b("Compressed"),
				Indexing:     r.b("IndexingEnabled"),
				BootVolume:   r.b("BootVolume"),
				SystemVolume: r.b("SystemVolume"),
				PageFile:     r.b("PageFilePresent"),
			})
		}
	}
	const fs = `SYSTEM\CurrentControlSet\Control\FileSystem`
	st.FS.Disable8dot3 = regInt(registry.LOCAL_MACHINE, fs, "NtfsDisable8dot3NameCreation")
	st.FS.DisableLastAccess = regInt(registry.LOCAL_MACHINE, fs, "NtfsDisableLastAccessUpdate")

	// The Storage Management API (root\Microsoft\Windows\Storage).
	rows, err := wmiQuery(nsStorage, "SELECT * FROM MSFT_PhysicalDisk")
	if err != nil {
		errs = append(errs, fmt.Errorf("storage management API: %w", err))
		return st, joinErrs(errs)
	}
	st.SpacesAvailable = true
	for _, r := range rows {
		st.PhysicalDisks = append(st.PhysicalDisks, PhysicalDisk{
			DeviceID:           r.str("DeviceId"),
			FriendlyName:       r.str("FriendlyName"),
			MediaType:          r.i("MediaType"),
			BusType:            r.i("BusType"),
			Size:               r.u64("Size"),
			HealthStatus:       r.i("HealthStatus"),
			Firmware:           r.str("FirmwareVersion"),
			SpindleSpeed:       uint32(r.u64("SpindleSpeed")),
			LogicalSectorSize:  r.u64("LogicalSectorSize"),
			PhysicalSectorSize: r.u64("PhysicalSectorSize"),
		})
	}
	if rows, err := wmiQuery(nsStorage, "SELECT * FROM MSFT_Disk"); err == nil {
		for _, r := range rows {
			st.Disks = append(st.Disks, Disk{
				Number:         r.i("Number"),
				FriendlyName:   r.str("FriendlyName"),
				PartitionStyle: r.i("PartitionStyle"),
				Size:           r.u64("Size"),
				BusType:        r.i("BusType"),
				IsBoot:         r.b("IsBoot"),
				IsSystem:       r.b("IsSystem"),
				IsOffline:      r.b("IsOffline"),
				IsReadOnly:     r.b("IsReadOnly"),
			})
		}
	} else {
		errs = append(errs, err)
	}
	if rows, err := wmiQuery(nsStorage, "SELECT * FROM MSFT_Partition"); err == nil {
		for _, r := range rows {
			st.Partitions = append(st.Partitions, Partition{
				DiskNumber:      r.i("DiskNumber"),
				PartitionNumber: r.i("PartitionNumber"),
				Offset:          r.u64("Offset"),
				Size:            r.u64("Size"),
				DriveLetter:     r.char16("DriveLetter"),
				GptType:         strings.ToLower(strings.Trim(r.str("GptType"), "{}")),
				MbrType:         r.i("MbrType"),
				AccessPaths:     r.strs("AccessPaths"),
			})
		}
	} else {
		errs = append(errs, err)
	}
	if rows, err := wmiQuery(nsStorage, "SELECT * FROM MSFT_StoragePool WHERE IsPrimordial = FALSE"); err == nil {
		for _, r := range rows {
			st.Pools = append(st.Pools, StoragePool{
				FriendlyName:  r.str("FriendlyName"),
				Size:          r.u64("Size"),
				AllocatedSize: r.u64("AllocatedSize"),
				HealthStatus:  r.i("HealthStatus"),
				IsReadOnly:    r.b("IsReadOnly"),
			})
		}
	} else {
		errs = append(errs, err)
	}
	if rows, err := wmiQuery(nsStorage, "SELECT * FROM MSFT_VirtualDisk"); err == nil {
		for _, r := range rows {
			st.VirtualDisks = append(st.VirtualDisks, VirtualDisk{
				FriendlyName:     r.str("FriendlyName"),
				Resiliency:       r.str("ResiliencySettingName"),
				Size:             r.u64("Size"),
				FootprintOnPool:  r.u64("FootprintOnPool"),
				HealthStatus:     r.i("HealthStatus"),
				NumberOfColumns:  r.i("NumberOfColumns"),
				DataCopies:       r.i("NumberOfDataCopies"),
				Interleave:       r.u64("Interleave"),
				ProvisioningType: r.i("ProvisioningType"),
				WriteCacheSize:   r.u64("WriteCacheSize"),
			})
		}
	} else {
		errs = append(errs, err)
	}
	return st, joinErrs(errs)
}

// ---- RAID -------------------------------------------------------------------

type vendorTool struct {
	exes []string
	args []string
}

var vendorTools = map[string]vendorTool{
	raidMegaRAID: {exes: []string{"storcli64.exe", "perccli64.exe", "storcli.exe", "perccli.exe"}, args: []string{"/call", "show"}},
	raidMegaCLI:  {exes: []string{"MegaCli64.exe", "MegaCli.exe"}, args: []string{"-LdPdInfo", "-aALL", "-NoLog"}},
	raidHP:       {exes: []string{"ssacli.exe", "hpssacli.exe", "hpacucli.exe"}, args: []string{"ctrl", "all", "show", "config"}},
	raidAdaptec:  {exes: []string{"arcconf.exe"}, args: []string{"GETCONFIG", "1"}},
}

const maxVendorOutputLines = 300

func collectRAID() (RAIDInfo, error) {
	var errs []error
	ri := RAIDInfo{}
	for _, class := range []string{"Win32_SCSIController", "Win32_IDEController"} {
		rows, err := wmiQuery(nsCIMV2, "SELECT * FROM "+class)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, r := range rows {
			ri.Controllers = append(ri.Controllers, StorageController{
				Name:         r.str("Name"),
				Manufacturer: r.str("Manufacturer"),
				DriverName:   r.str("DriverName"),
				Status:       r.str("Status"),
			})
		}
	}

	seen := map[string]bool{}
	for _, c := range ri.Controllers {
		kind := raidKind(c)
		if kind == "" || seen[kind] {
			continue
		}
		seen[kind] = true
		kinds := []string{kind}
		if kind == raidMegaRAID {
			kinds = append(kinds, raidMegaCLI)
		}
		for _, k := range kinds {
			vt, ok := vendorTools[k]
			if !ok {
				continue
			}
			path := findExecutable(vt.exes)
			if path == "" {
				continue
			}
			ri.VendorTools = append(ri.VendorTools, runVendorTool(path, vt.args))
			break
		}
	}
	return ri, joinErrs(errs)
}

func findExecutable(names []string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	var roots []string
	for _, env := range []string{"ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"} {
		if v := os.Getenv(env); v != "" {
			roots = append(roots, v)
		}
	}
	for _, root := range roots {
		for _, n := range names {
			for _, pattern := range []string{`*\` + n, `*\*\` + n, `*\*\*\` + n} {
				if m, _ := filepath.Glob(filepath.Join(root, pattern)); len(m) > 0 {
					return m[0]
				}
			}
		}
	}
	return ""
}

func runVendorTool(path string, args []string) VendorToolOutput {
	out := VendorToolOutput{Tool: filepath.Base(path), Command: filepath.Base(path) + " " + strings.Join(args, " ")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	buf, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		out.Error = err.Error()
	}
	lines := strings.Split(strings.ReplaceAll(string(buf), "\r\n", "\n"), "\n")
	if len(lines) > maxVendorOutputLines {
		lines = append(lines[:maxVendorOutputLines], fmt.Sprintf("[... output truncated to %d lines ...]", maxVendorOutputLines))
	}
	out.Output = strings.TrimRight(strings.Join(lines, "\n"), "\n")
	return out
}

// ---- network ----------------------------------------------------------------

var congestionProviders = map[int]string{0: "Default", 1: "NewReno", 2: "CTCP", 3: "DCTCP", 4: "LEDBAT", 5: "CUBIC", 6: "BBR2"}
var autoTuningLevels = map[int]string{0: "Disabled", 1: "HighlyRestricted", 2: "Restricted", 3: "Normal", 4: "Experimental"}

func collectNetwork() (NetworkInfo, error) {
	var errs []error
	ni := NetworkInfo{}

	rows, err := wmiQuery(nsStdCIMV2, "SELECT * FROM MSFT_NetAdapter")
	errs = append(errs, err)
	for _, r := range rows {
		status := "Unknown"
		switch {
		case r.i("InterfaceAdminStatus") == 2:
			status = "Disabled"
		case r.i("InterfaceOperationalStatus") == 1:
			status = "Up"
		case r.i("MediaConnectState") == 2:
			status = "Disconnected"
		case r.i("InterfaceOperationalStatus") == 2:
			status = "Down"
		}
		ni.Adapters = append(ni.Adapters, NetAdapter{
			Name:              r.str("Name"),
			Description:       r.str("InterfaceDescription"),
			Status:            status,
			SpeedBps:          r.u64("Speed"),
			FullDuplex:        r.b("FullDuplex"),
			MTU:               uint32(r.u64("MtuSize")),
			MAC:               formatMAC(r.str("PermanentAddress")),
			Virtual:           r.b("Virtual"),
			HardwareInterface: r.b("HardwareInterface"),
			DriverVersion:     r.str("DriverVersionString"),
		})
	}

	if rows, err := wmiQuery(nsStdCIMV2, "SELECT * FROM MSFT_NetAdapterStatisticsSettingData"); err == nil {
		for _, r := range rows {
			ni.Stats = append(ni.Stats, NetStats{
				Name:      r.str("Name"),
				RxBytes:   r.u64("ReceivedBytes"),
				RxPackets: r.u64("ReceivedUnicastPackets") + r.u64("ReceivedMulticastPackets") + r.u64("ReceivedBroadcastPackets"),
				RxErrors:  r.u64("ReceivedPacketErrors"),
				TxBytes:   r.u64("SentBytes"),
				TxPackets: r.u64("SentUnicastPackets") + r.u64("SentMulticastPackets") + r.u64("SentBroadcastPackets"),
				TxErrors:  r.u64("OutboundPacketErrors"),
			})
		}
	} else {
		errs = append(errs, err)
	}

	ni.TCP.TimedWaitDelay = -1
	ni.TCP.MaxUserPort = -1
	const tcpip = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	if v := regInt(registry.LOCAL_MACHINE, tcpip, "TcpTimedWaitDelay"); v >= 0 {
		ni.TCP.TimedWaitDelay = int(v)
	}
	if v := regInt(registry.LOCAL_MACHINE, tcpip, "MaxUserPort"); v >= 0 {
		ni.TCP.MaxUserPort = int(v)
	}
	if rows, err := wmiQuery(nsStdCIMV2, "SELECT * FROM MSFT_NetTCPSetting"); err == nil {
		var cong, tune []string
		for _, r := range rows {
			name := r.str("SettingName")
			if ni.TCP.DynamicPortStart == 0 && r.i("DynamicPortRangeStartPort") > 0 {
				ni.TCP.DynamicPortStart = r.i("DynamicPortRangeStartPort")
				ni.TCP.DynamicPortCount = r.i("DynamicPortRangeNumberOfPorts")
			}
			if name != "Internet" && name != "Datacenter" {
				continue
			}
			if _, ok := r["CongestionProvider"]; ok && r["CongestionProvider"] != nil {
				cp := r.i("CongestionProvider")
				cn, ok := congestionProviders[cp]
				if !ok {
					cn = strconv.Itoa(cp)
				}
				cong = append(cong, name+"="+cn)
			}
			if _, ok := r["AutoTuningLevelLocal"]; ok && r["AutoTuningLevelLocal"] != nil {
				at := r.i("AutoTuningLevelLocal")
				an, ok := autoTuningLevels[at]
				if !ok {
					an = strconv.Itoa(at)
				}
				tune = append(tune, name+"="+an)
			}
		}
		sort.Strings(cong)
		sort.Strings(tune)
		ni.TCP.CongestionControl = strings.Join(cong, ", ")
		ni.TCP.AutoTuningLevel = strings.Join(tune, ", ")
	} else {
		errs = append(errs, err)
	}

	conns, err := tcpConnections()
	errs = append(errs, err)
	ni.Connections = conns

	names, err := processNames()
	errs = append(errs, err)
	ni.ProcessNames = map[uint32]string{}
	for _, c := range conns {
		if n, ok := names[c.PID]; ok {
			ni.ProcessNames[c.PID] = n
		}
	}
	return ni, joinErrs(errs)
}

func processNames() (map[uint32]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap) //nolint:errcheck
	out := map[uint32]string{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil, err
	}
	for {
		out[pe.ProcessID] = windows.UTF16ToString(pe.ExeFile[:])
		if err := windows.Process32Next(snap, &pe); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return out, err
		}
	}
	return out, nil
}

// ---- services ---------------------------------------------------------------

func collectServices() ([]Service, error) {
	rows, err := wmiQuery(nsCIMV2, "SELECT Name, DisplayName, State, StartMode, ProcessId, PathName FROM Win32_Service")
	if err != nil {
		return nil, err
	}
	out := make([]Service, 0, len(rows))
	for _, r := range rows {
		out = append(out, Service{
			Name:        r.str("Name"),
			DisplayName: r.str("DisplayName"),
			State:       r.str("State"),
			StartMode:   r.str("StartMode"),
			PID:         uint32(r.u64("ProcessId")),
			Image:       serviceImage(r.str("PathName")),
		})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// ---- memory management ------------------------------------------------------

func collectMemoryMgmt() (MemoryMgmt, error) {
	mm := MemoryMgmt{LargePageMinimum: largePageMinimum()}
	holders, err := accountsWithRight("SeLockMemoryPrivilege")
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			mm.LockPagesError = "requires administrator"
		} else {
			mm.LockPagesError = err.Error()
		}
	}
	mm.LockPagesHolders = holders
	return mm, nil
}

// ---- security ---------------------------------------------------------------

func collectSecurity() (SecurityInfo, error) {
	sec := SecurityInfo{}
	var errs []error
	if rows, err := wmiQuery(nsDefender, "SELECT * FROM MSFT_MpComputerStatus"); err == nil && len(rows) > 0 {
		r := rows[0]
		sec.DefenderPresent = true
		sec.DefenderAVEnabled = r.b("AntivirusEnabled")
		sec.DefenderRealTime = r.b("RealTimeProtectionEnabled")
		sec.DefenderRunningMode = r.str("AMRunningMode")
		if !r.b("AMServiceEnabled") && sec.DefenderRunningMode == "" {
			sec.DefenderRunningMode = "service disabled"
		}
		if prefs, err := wmiQuery(nsDefender, "SELECT ExclusionPath, ExclusionProcess FROM MSFT_MpPreference"); err == nil && len(prefs) > 0 {
			p := prefs[0]
			paths := p.strs("ExclusionPath")
			procs := p.strs("ExclusionProcess")
			if len(paths) == 1 && strings.HasPrefix(paths[0], "N/A") {
				sec.ExclusionsNote = "requires administrator"
			} else {
				sec.ExclusionPaths = paths
				sec.ExclusionProcesses = procs
			}
		} else if err != nil {
			sec.ExclusionsNote = "unable to read exclusions"
		}
	}
	if rows, err := wmiQuery(nsStdCIMV2, "SELECT Name, Enabled FROM MSFT_NetFirewallProfile"); err == nil {
		for _, r := range rows {
			sec.Firewall = append(sec.Firewall, FirewallProfile{Name: r.str("Name"), Enabled: r.i("Enabled")})
		}
	} else {
		errs = append(errs, err)
	}
	return sec, joinErrs(errs)
}

// ---- sampling (vmstat and top) ----------------------------------------------

var vmstatCounters = []string{
	`\System\Processor Queue Length`,
	`\PhysicalDisk(_Total)\Current Disk Queue Length`,
	`\Memory\Pages Input/sec`,
	`\Memory\Pages Output/sec`,
	`\PhysicalDisk(_Total)\Disk Read Bytes/sec`,
	`\PhysicalDisk(_Total)\Disk Write Bytes/sec`,
	`\Processor Information(_Total)\Interrupts/sec`,
	`\System\Context Switches/sec`,
	`\Processor Information(_Total)\% User Time`,
	`\Processor Information(_Total)\% Privileged Time`,
	`\Processor Information(_Total)\% Idle Time`,
	`\Processor Information(_Total)\% Interrupt Time`,
	`\Processor Information(_Total)\% DPC Time`,
}

type procSnap struct {
	name                   string
	prio, threads, handles int
	ws, private, virtual   uint64
	cpu100ns               uint64
	created                time.Time
}

func processSnapshot() (map[uint32]procSnap, time.Time, error) {
	rows, err := wmiQuery(nsCIMV2, "SELECT ProcessId, Name, Priority, ThreadCount, HandleCount, "+
		"WorkingSetSize, PrivatePageCount, VirtualSize, KernelModeTime, UserModeTime, CreationDate FROM Win32_Process")
	now := time.Now()
	if err != nil {
		return nil, now, err
	}
	out := make(map[uint32]procSnap, len(rows))
	for _, r := range rows {
		out[uint32(r.u64("ProcessId"))] = procSnap{
			name:     r.str("Name"),
			prio:     r.i("Priority"),
			threads:  r.i("ThreadCount"),
			handles:  r.i("HandleCount"),
			ws:       r.u64("WorkingSetSize"),
			private:  r.u64("PrivatePageCount"),
			virtual:  r.u64("VirtualSize"),
			cpu100ns: r.u64("KernelModeTime") + r.u64("UserModeTime"),
			created:  r.t("CreationDate"),
		}
	}
	return out, now, nil
}

const topN = 10

func collectSampling(sleep int) ([]VmstatSample, ProcessInfo, error) {
	var errs []error
	pinfo := ProcessInfo{LogicalCPUs: int(windows.GetActiveProcessorCount(windows.ALL_PROCESSOR_GROUPS))}

	before, t0, err := processSnapshot()
	errs = append(errs, err)

	var samples []VmstatSample
	q, err := newPDHQuery(vmstatCounters)
	if err != nil {
		errs = append(errs, err)
		time.Sleep(time.Duration(sleep) * time.Second)
	} else {
		defer q.close()
		if err := q.collect(); err != nil {
			errs = append(errs, err)
		}
		for i := 0; i < sleep; i++ {
			time.Sleep(time.Second)
			if err := q.collect(); err != nil {
				errs = append(errs, err)
				continue
			}
			v := q.values()
			samples = append(samples, VmstatSample{
				ProcQueue:     v[0],
				DiskQueue:     v[1],
				PagesIn:       v[2],
				PagesOut:      v[3],
				ReadKB:        v[4] / 1024,
				WriteKB:       v[5] / 1024,
				Interrupts:    v[6],
				CtxSwitches:   v[7],
				User:          v[8],
				Privileged:    v[9],
				Idle:          v[10],
				InterruptTime: v[11] + v[12],
			})
		}
	}

	after, t1, err := processSnapshot()
	errs = append(errs, err)
	interval := t1.Sub(t0).Seconds()
	pinfo.SampleSeconds = interval

	var procs []Process
	for pid, a := range after {
		if pid == 0 { // System Idle Process
			continue
		}
		p := Process{
			PID: pid, Name: a.name, Priority: a.prio, Threads: a.threads, Handles: a.handles,
			WorkingSet: a.ws, Private: a.private, Virtual: a.virtual,
			CPUSeconds: float64(a.cpu100ns) / 1e7,
		}
		if b, ok := before[pid]; ok && b.created.Equal(a.created) && interval > 0 && a.cpu100ns >= b.cpu100ns {
			p.CPUPercent = float64(a.cpu100ns-b.cpu100ns) / 1e7 / interval * 100
		}
		procs = append(procs, p)
	}

	sort.Slice(procs, func(i, j int) bool {
		if procs[i].CPUPercent != procs[j].CPUPercent {
			return procs[i].CPUPercent > procs[j].CPUPercent
		}
		return procs[i].CPUSeconds > procs[j].CPUSeconds
	})
	pinfo.Top = topWithUsers(procs)

	sort.Slice(procs, func(i, j int) bool { return procs[i].WorkingSet > procs[j].WorkingSet })
	pinfo.TopMem = topWithUsers(procs)

	return samples, pinfo, joinErrs(errs)
}

func topWithUsers(procs []Process) []Process {
	n := topN
	if len(procs) < n {
		n = len(procs)
	}
	out := make([]Process, n)
	copy(out, procs[:n])
	for i := range out {
		out[i].User = processUser(out[i].PID)
	}
	return out
}
