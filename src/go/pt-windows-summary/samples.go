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

// The data model. Everything the collector gathers ends up in a Samples
// value, which is what --save-samples writes to disk (as JSON) and what
// --read-samples reads back. The report is rendered only from this struct, so
// a report can be re-created on any platform from saved samples.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	samplesFile    = "summary.json"
	samplesErrFile = "collect.err"
	samplesFormat  = 1
)

type Samples struct {
	Format      int       `json:"format"`
	ToolVersion string    `json:"tool_version"`
	CollectedAt time.Time `json:"collected_at"`
	// LocalTZ is the local time zone abbreviation and offset, e.g. "CET +0100".
	LocalTZ      string `json:"local_tz"`
	TimeZoneName string `json:"time_zone_name"`

	Options SampleOptions `json:"options"`

	System     SystemInfo     `json:"system"`
	CPU        CPUInfo        `json:"cpu"`
	Memory     MemoryInfo     `json:"memory"`
	Storage    StorageInfo    `json:"storage"`
	RAID       RAIDInfo       `json:"raid"`
	Network    NetworkInfo    `json:"network"`
	Processes  ProcessInfo    `json:"processes"`
	Vmstat     []VmstatSample `json:"vmstat"`
	MemoryMgmt MemoryMgmt     `json:"memory_management"`
	Security   SecurityInfo   `json:"security"`

	// Errors holds one entry per collector that failed or partially failed,
	// keyed by collector name. They are printed at the end of the report.
	Errors map[string]string `json:"errors,omitempty"`
}

type SampleOptions struct {
	SummarizeMounts    bool `json:"summarize_mounts"`
	SummarizeNetwork   bool `json:"summarize_network"`
	SummarizeProcesses bool `json:"summarize_processes"`
	Sleep              int  `json:"sleep"`
}

type SystemInfo struct {
	Hostname     string `json:"hostname"`
	Domain       string `json:"domain"`
	PartOfDomain bool   `json:"part_of_domain"`
	DomainRole   int    `json:"domain_role"`
	Elevated     bool   `json:"elevated"`

	Manufacturer    string `json:"manufacturer"`
	Model           string `json:"model"`
	ProductVersion  string `json:"product_version"`
	SerialNumber    string `json:"serial_number"`
	ChassisTypes    []int  `json:"chassis_types"`
	ChassisAssetTag string `json:"chassis_asset_tag"`
	BIOSVendor      string `json:"bios_vendor"`
	BIOSVersion     string `json:"bios_version"`
	BIOSReleaseDate string `json:"bios_release_date"`

	HypervisorPresent bool `json:"hypervisor_present"`

	OSCaption        string `json:"os_caption"`
	OSVersion        string `json:"os_version"`
	BuildNumber      string `json:"build_number"`
	UBR              uint32 `json:"ubr"`
	DisplayVersion   string `json:"display_version"`
	EditionID        string `json:"edition_id"`
	InstallationType string `json:"installation_type"`
	ProductType      int    `json:"product_type"`
	// NativeArch is the OS architecture as PROCESSOR_ARCHITECTURE reports it
	// for the native OS: AMD64, ARM64 or x86.
	NativeArch  string    `json:"native_arch"`
	InstallDate time.Time `json:"install_date"`
	LastBoot    time.Time `json:"last_boot"`

	TimeSyncType   string `json:"time_sync_type"`
	TimeSyncServer string `json:"time_sync_server"`

	PendingReboot        []string `json:"pending_reboot"`
	HotfixCount          int      `json:"hotfix_count"`
	LastHotfixID         string   `json:"last_hotfix_id"`
	LastHotfixInstalled  string   `json:"last_hotfix_installed"`
	HotfixCollectionNote string   `json:"hotfix_collection_note,omitempty"`
}

type CPUInfo struct {
	Sockets   []CPUSocket `json:"sockets"`
	Caches    []CPUCache  `json:"caches"`
	PowerPlan string      `json:"power_plan"`
	NUMA      []NUMANode  `json:"numa"`
}

type CPUSocket struct {
	Name              string `json:"name"`
	Manufacturer      string `json:"manufacturer"`
	SocketDesignation string `json:"socket_designation"`
	Cores             int    `json:"cores"`
	Logical           int    `json:"logical"`
	CurrentMHz        int    `json:"current_mhz"`
	MaxMHz            int    `json:"max_mhz"`
	L2KB              int    `json:"l2_kb"`
	L3KB              int    `json:"l3_kb"`
	Architecture      int    `json:"architecture"`
	DataWidth         int    `json:"data_width"`
	AddressWidth      int    `json:"address_width"`
}

type CPUCache struct {
	Purpose       string `json:"purpose"`
	Level         int    `json:"level"`
	InstalledKB   uint64 `json:"installed_kb"`
	Associativity int    `json:"associativity"`
	CacheType     int    `json:"cache_type"`
	WritePolicy   int    `json:"write_policy"`
	Location      int    `json:"location"`
}

type NUMANode struct {
	Node        int    `json:"node"`
	TotalMB     uint64 `json:"total_mb"`
	FreeMB      uint64 `json:"free_mb"`
	AvailableMB uint64 `json:"available_mb"`
	CPUs        string `json:"cpus"`
}

type MemoryInfo struct {
	TotalPhys   uint64 `json:"total_phys"`
	AvailPhys   uint64 `json:"avail_phys"`
	FreeZero    uint64 `json:"free_zero"`
	Standby     uint64 `json:"standby"`
	Modified    uint64 `json:"modified"`
	CacheBytes  uint64 `json:"cache_bytes"`
	CommitTotal uint64 `json:"commit_total"`
	CommitLimit uint64 `json:"commit_limit"`
	CommitPeak  uint64 `json:"commit_peak"`
	PagedPool   uint64 `json:"paged_pool"`
	NonPaged    uint64 `json:"nonpaged_pool"`
	UsedRSS     uint64 `json:"used_rss"`

	HandleCount  uint32 `json:"handle_count"`
	ProcessCount uint32 `json:"process_count"`
	ThreadCount  uint32 `json:"thread_count"`

	AutomaticPagefile bool              `json:"automatic_pagefile"`
	Pagefiles         []Pagefile        `json:"pagefiles"`
	PagefileSettings  []PagefileSetting `json:"pagefile_settings"`

	DIMMs         []DIMM `json:"dimms"`
	SlotsTotal    int    `json:"slots_total"`
	MaxCapacityKB uint64 `json:"max_capacity_kb"`
}

type Pagefile struct {
	Name          string `json:"name"`
	AllocatedMB   uint64 `json:"allocated_mb"`
	CurrentUsedMB uint64 `json:"current_used_mb"`
	PeakUsedMB    uint64 `json:"peak_used_mb"`
}

type PagefileSetting struct {
	Name      string `json:"name"`
	InitialMB uint64 `json:"initial_mb"`
	MaximumMB uint64 `json:"maximum_mb"`
}

type DIMM struct {
	Locator          string `json:"locator"`
	BankLabel        string `json:"bank_label"`
	Capacity         uint64 `json:"capacity"`
	Speed            int    `json:"speed"`
	ConfiguredSpeed  int    `json:"configured_speed"`
	FormFactor       int    `json:"form_factor"`
	SMBIOSMemoryType int    `json:"smbios_memory_type"`
	MemoryType       int    `json:"memory_type"`
	TypeDetail       int    `json:"type_detail"`
	Manufacturer     string `json:"manufacturer"`
	PartNumber       string `json:"part_number"`
}

type StorageInfo struct {
	Volumes       []Volume       `json:"volumes"`
	FS            FSSettings     `json:"fs_settings"`
	PhysicalDisks []PhysicalDisk `json:"physical_disks"`
	Disks         []Disk         `json:"disks"`
	Partitions    []Partition    `json:"partitions"`
	Pools         []StoragePool  `json:"pools"`
	VirtualDisks  []VirtualDisk  `json:"virtual_disks"`
	// SpacesAvailable is false when the Storage Management API is missing.
	SpacesAvailable bool `json:"spaces_available"`
}

type Volume struct {
	Name         string `json:"name"`
	Label        string `json:"label"`
	DriveLetter  string `json:"drive_letter"`
	FileSystem   string `json:"file_system"`
	DriveType    int    `json:"drive_type"`
	Capacity     uint64 `json:"capacity"`
	FreeSpace    uint64 `json:"free_space"`
	BlockSize    uint64 `json:"block_size"`
	Compressed   bool   `json:"compressed"`
	Indexing     bool   `json:"indexing"`
	BootVolume   bool   `json:"boot_volume"`
	SystemVolume bool   `json:"system_volume"`
	PageFile     bool   `json:"page_file"`
}

// FSSettings holds the raw values of global NTFS behaviour settings. A value
// of -1 means "not set".
type FSSettings struct {
	Disable8dot3      int64 `json:"disable_8dot3"`
	DisableLastAccess int64 `json:"disable_last_access"`
}

type PhysicalDisk struct {
	DeviceID           string `json:"device_id"`
	FriendlyName       string `json:"friendly_name"`
	MediaType          int    `json:"media_type"`
	BusType            int    `json:"bus_type"`
	Size               uint64 `json:"size"`
	HealthStatus       int    `json:"health_status"`
	Firmware           string `json:"firmware"`
	SpindleSpeed       uint32 `json:"spindle_speed"`
	LogicalSectorSize  uint64 `json:"logical_sector_size"`
	PhysicalSectorSize uint64 `json:"physical_sector_size"`
}

type Disk struct {
	Number         int    `json:"number"`
	FriendlyName   string `json:"friendly_name"`
	PartitionStyle int    `json:"partition_style"`
	Size           uint64 `json:"size"`
	BusType        int    `json:"bus_type"`
	IsBoot         bool   `json:"is_boot"`
	IsSystem       bool   `json:"is_system"`
	IsOffline      bool   `json:"is_offline"`
	IsReadOnly     bool   `json:"is_read_only"`
}

type Partition struct {
	DiskNumber      int      `json:"disk_number"`
	PartitionNumber int      `json:"partition_number"`
	Offset          uint64   `json:"offset"`
	Size            uint64   `json:"size"`
	DriveLetter     string   `json:"drive_letter"`
	GptType         string   `json:"gpt_type"`
	MbrType         int      `json:"mbr_type"`
	AccessPaths     []string `json:"access_paths"`
}

type StoragePool struct {
	FriendlyName  string `json:"friendly_name"`
	Size          uint64 `json:"size"`
	AllocatedSize uint64 `json:"allocated_size"`
	HealthStatus  int    `json:"health_status"`
	IsReadOnly    bool   `json:"is_read_only"`
}

type VirtualDisk struct {
	FriendlyName     string `json:"friendly_name"`
	Resiliency       string `json:"resiliency"`
	Size             uint64 `json:"size"`
	FootprintOnPool  uint64 `json:"footprint_on_pool"`
	HealthStatus     int    `json:"health_status"`
	NumberOfColumns  int    `json:"number_of_columns"`
	DataCopies       int    `json:"data_copies"`
	Interleave       uint64 `json:"interleave"`
	ProvisioningType int    `json:"provisioning_type"`
	WriteCacheSize   uint64 `json:"write_cache_size"`
}

type RAIDInfo struct {
	Controllers []StorageController `json:"controllers"`
	VendorTools []VendorToolOutput  `json:"vendor_tools"`
}

type StorageController struct {
	Name         string `json:"name"`
	Manufacturer string `json:"manufacturer"`
	DriverName   string `json:"driver_name"`
	Status       string `json:"status"`
}

type VendorToolOutput struct {
	Tool    string `json:"tool"`
	Command string `json:"command"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

type NetworkInfo struct {
	Adapters    []NetAdapter    `json:"adapters"`
	Stats       []NetStats      `json:"stats"`
	TCP         TCPSettings     `json:"tcp"`
	Connections []TCPConnection `json:"connections"`
	// ProcessNames maps PIDs that own TCP sockets to their image name.
	ProcessNames map[uint32]string `json:"process_names"`
}

type NetAdapter struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	Status            string `json:"status"`
	SpeedBps          uint64 `json:"speed_bps"`
	FullDuplex        bool   `json:"full_duplex"`
	MTU               uint32 `json:"mtu"`
	MAC               string `json:"mac"`
	Virtual           bool   `json:"virtual"`
	HardwareInterface bool   `json:"hardware_interface"`
	DriverVersion     string `json:"driver_version"`
}

type NetStats struct {
	Name      string `json:"name"`
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
}

type TCPSettings struct {
	DynamicPortStart  int    `json:"dynamic_port_start"`
	DynamicPortCount  int    `json:"dynamic_port_count"`
	TimedWaitDelay    int    `json:"timed_wait_delay"` // -1 = default
	MaxUserPort       int    `json:"max_user_port"`    // -1 = default
	CongestionControl string `json:"congestion_control"`
	AutoTuningLevel   string `json:"auto_tuning_level"`
}

type TCPConnection struct {
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	State      string `json:"state"`
	PID        uint32 `json:"pid"`
}

type ProcessInfo struct {
	// Top holds the busiest processes by CPU during the sampling interval.
	Top []Process `json:"top"`
	// TopMem holds the processes with the largest working sets.
	TopMem   []Process `json:"top_mem"`
	Services []Service `json:"services"`
	// SampleSeconds is the length of the interval used to compute %CPU.
	SampleSeconds float64 `json:"sample_seconds"`
	LogicalCPUs   int     `json:"logical_cpus"`
	TotalPhys     uint64  `json:"total_phys"`
}

type Process struct {
	PID        uint32  `json:"pid"`
	Name       string  `json:"name"`
	User       string  `json:"user"`
	Priority   int     `json:"priority"`
	Threads    int     `json:"threads"`
	Handles    int     `json:"handles"`
	WorkingSet uint64  `json:"working_set"`
	Private    uint64  `json:"private"`
	Virtual    uint64  `json:"virtual"`
	CPUPercent float64 `json:"cpu_percent"`
	CPUSeconds float64 `json:"cpu_seconds"`
}

type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	StartMode   string `json:"start_mode"`
	PID         uint32 `json:"pid"`
	// Image is the service executable path, without arguments, to avoid
	// leaking credentials that might be passed on the command line.
	Image string `json:"image"`
}

type VmstatSample struct {
	ProcQueue     float64 `json:"proc_queue"`
	DiskQueue     float64 `json:"disk_queue"`
	PagesIn       float64 `json:"pages_in"`
	PagesOut      float64 `json:"pages_out"`
	ReadKB        float64 `json:"read_kb"`
	WriteKB       float64 `json:"write_kb"`
	Interrupts    float64 `json:"interrupts"`
	CtxSwitches   float64 `json:"ctx_switches"`
	User          float64 `json:"user"`
	Privileged    float64 `json:"privileged"`
	Idle          float64 `json:"idle"`
	InterruptTime float64 `json:"interrupt_time"`
}

type MemoryMgmt struct {
	LargePageMinimum uint64   `json:"large_page_minimum"`
	LockPagesHolders []string `json:"lock_pages_holders"`
	LockPagesError   string   `json:"lock_pages_error,omitempty"`
}

type SecurityInfo struct {
	DefenderPresent     bool              `json:"defender_present"`
	DefenderAVEnabled   bool              `json:"defender_av_enabled"`
	DefenderRealTime    bool              `json:"defender_real_time"`
	DefenderRunningMode string            `json:"defender_running_mode"`
	ExclusionPaths      []string          `json:"exclusion_paths"`
	ExclusionProcesses  []string          `json:"exclusion_processes"`
	ExclusionsNote      string            `json:"exclusions_note,omitempty"`
	Firewall            []FirewallProfile `json:"firewall"`
}

type FirewallProfile struct {
	Name    string `json:"name"`
	Enabled int    `json:"enabled"` // 0 = false, 1 = true, 2 = not configured
}

func (s *Samples) addError(collector string, err error) {
	if err == nil {
		return
	}
	if s.Errors == nil {
		s.Errors = map[string]string{}
	}
	if prev, ok := s.Errors[collector]; ok {
		s.Errors[collector] = prev + "; " + err.Error()
		return
	}
	s.Errors[collector] = err.Error()
}

func saveSamples(dir string, s *Samples) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("cannot create samples directory %q: %w", dir, err)
	}
	buf, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, samplesFile), buf, 0o640); err != nil {
		return err
	}
	var errs []byte
	for _, k := range sortedKeys(s.Errors) {
		errs = append(errs, []byte(k+": "+s.Errors[k]+"\n")...)
	}
	return os.WriteFile(filepath.Join(dir, samplesErrFile), errs, 0o640)
}

func loadSamples(dir string) (*Samples, error) {
	buf, err := os.ReadFile(filepath.Join(dir, samplesFile))
	if err != nil {
		return nil, fmt.Errorf("the samples directory doesn't have a %s file: %w", samplesFile, err)
	}
	s := &Samples{}
	if err := json.Unmarshal(buf, s); err != nil {
		return nil, fmt.Errorf("cannot parse %s: %w", samplesFile, err)
	}
	if s.Format > samplesFormat {
		return nil, fmt.Errorf("samples format %d is newer than this tool supports (%d); please upgrade", s.Format, samplesFormat)
	}
	return s, nil
}
