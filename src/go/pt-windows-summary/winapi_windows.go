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

// Thin wrappers around Win32 APIs that golang.org/x/sys/windows doesn't cover.
// All of them exist on Windows 10 / Server 2016 and later (most of them since
// Windows Vista / Server 2008), which is the support floor of Go itself.

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modpdh      = windows.NewLazySystemDLL("pdh.dll")

	procGlobalMemoryStatusEx       = modkernel32.NewProc("GlobalMemoryStatusEx")
	procK32GetPerformanceInfo      = modkernel32.NewProc("K32GetPerformanceInfo")
	procGetNumaHighestNodeNumber   = modkernel32.NewProc("GetNumaHighestNodeNumber")
	procGetNumaNodeProcessorMaskEx = modkernel32.NewProc("GetNumaNodeProcessorMaskEx")
	procGetNumaNodeProcessorMask2  = modkernel32.NewProc("GetNumaNodeProcessorMask2")
	procGetLargePageMinimum        = modkernel32.NewProc("GetLargePageMinimum")

	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")

	procLsaOpenPolicy                     = modadvapi32.NewProc("LsaOpenPolicy")
	procLsaEnumerateAccountsWithUserRight = modadvapi32.NewProc("LsaEnumerateAccountsWithUserRight")
	procLsaFreeMemory                     = modadvapi32.NewProc("LsaFreeMemory")
	procLsaClose                          = modadvapi32.NewProc("LsaClose")
	procLsaNtStatusToWinError             = modadvapi32.NewProc("LsaNtStatusToWinError")

	procPdhOpenQueryW               = modpdh.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounterW       = modpdh.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData         = modpdh.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterValue = modpdh.NewProc("PdhGetFormattedCounterValue")
	procPdhCloseQuery               = modpdh.NewProc("PdhCloseQuery")
)

// ---- memory ---------------------------------------------------------------

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func globalMemoryStatus() (*memoryStatusEx, error) {
	m := &memoryStatusEx{}
	m.Length = uint32(unsafe.Sizeof(*m))
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(m)))
	if r == 0 {
		return nil, fmt.Errorf("GlobalMemoryStatusEx: %w", err)
	}
	return m, nil
}

type performanceInformation struct {
	Cb                uint32
	CommitTotal       uintptr
	CommitLimit       uintptr
	CommitPeak        uintptr
	PhysicalTotal     uintptr
	PhysicalAvailable uintptr
	SystemCache       uintptr
	KernelTotal       uintptr
	KernelPaged       uintptr
	KernelNonpaged    uintptr
	PageSize          uintptr
	HandleCount       uint32
	ProcessCount      uint32
	ThreadCount       uint32
}

func getPerformanceInfo() (*performanceInformation, error) {
	p := &performanceInformation{}
	p.Cb = uint32(unsafe.Sizeof(*p))
	r, _, err := procK32GetPerformanceInfo.Call(uintptr(unsafe.Pointer(p)), uintptr(p.Cb))
	if r == 0 {
		return nil, fmt.Errorf("GetPerformanceInfo: %w", err)
	}
	return p, nil
}

func largePageMinimum() uint64 {
	if procGetLargePageMinimum.Find() != nil {
		return 0
	}
	r, _, _ := procGetLargePageMinimum.Call()
	return uint64(r)
}

// ---- NUMA -----------------------------------------------------------------

type groupAffinity struct {
	Mask     uintptr
	Group    uint16
	Reserved [3]uint16
}

// numaNodeCPUs returns the highest NUMA node number and, for each node, the
// list of logical processors (numbered group*64+bit) in compressed form.
func numaNodeCPUs() (map[int]string, error) {
	var highest uint32
	r, _, err := procGetNumaHighestNodeNumber.Call(uintptr(unsafe.Pointer(&highest)))
	if r == 0 {
		return nil, fmt.Errorf("GetNumaHighestNodeNumber: %w", err)
	}
	out := map[int]string{}
	for node := 0; node <= int(highest); node++ {
		masks, ok := numaNodeMasks(node)
		if !ok {
			continue
		}
		var cpus []int
		for _, ga := range masks {
			bits := int(unsafe.Sizeof(ga.Mask) * 8)
			for b := 0; b < bits; b++ {
				if ga.Mask&(1<<uint(b)) != 0 {
					cpus = append(cpus, int(ga.Group)*64+b)
				}
			}
		}
		out[node] = compressRanges(cpus)
	}
	return out, nil
}

// numaNodeMasks returns the processor masks of a NUMA node. Since Windows 11
// and Server 2022 a node can span several processor groups (e.g. one node
// with more than 64 logical CPUs); GetNumaNodeProcessorMask2 reports all of
// them. Older versions only have GetNumaNodeProcessorMaskEx, and there a node
// is always within a single group.
func numaNodeMasks(node int) ([]groupAffinity, bool) {
	if procGetNumaNodeProcessorMask2.Find() == nil {
		masks := make([]groupAffinity, 64)
		var required uint16
		r, _, _ := procGetNumaNodeProcessorMask2.Call(uintptr(node),
			uintptr(unsafe.Pointer(&masks[0])), uintptr(len(masks)), uintptr(unsafe.Pointer(&required)))
		if r != 0 && int(required) <= len(masks) {
			return masks[:required], true
		}
	}
	var ga groupAffinity
	r, _, _ := procGetNumaNodeProcessorMaskEx.Call(uintptr(node), uintptr(unsafe.Pointer(&ga)))
	if r == 0 {
		return nil, false
	}
	return []groupAffinity{ga}, true
}

// ---- TCP connections ------------------------------------------------------

const (
	afInet                = 2
	afInet6               = 23
	tcpTableOwnerPIDAll   = 5
	errInsufficientBuffer = 122
)

var tcpStates = map[uint32]string{
	1:  "CLOSE",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RECV",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT1",
	7:  "FIN_WAIT2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

func tcpState(s uint32) string {
	if n, ok := tcpStates[s]; ok {
		return n
	}
	return "UNKNOWN"
}

func extendedTCPTable(af uint32) ([]byte, error) {
	size := uint32(64 * 1024)
	for i := 0; i < 8; i++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, uintptr(af), tcpTableOwnerPIDAll, 0)
		if r == 0 {
			return buf[:size], nil
		}
		if r != errInsufficientBuffer {
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", windows.Errno(r))
		}
		size += 16 * 1024 // the table might have grown in between calls
	}
	return nil, fmt.Errorf("GetExtendedTcpTable: table keeps growing")
}

func portFromDword(dw uint32) uint16 {
	// The port is stored in network byte order in the low 16 bits.
	return uint16(dw&0xff)<<8 | uint16((dw>>8)&0xff)
}

func tcpConnections() ([]TCPConnection, error) {
	var out []TCPConnection

	buf, err := extendedTCPTable(afInet)
	if err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	const row4 = 24
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*row4
		if off+row4 > len(buf) {
			break
		}
		rw := buf[off : off+row4]
		state := binary.LittleEndian.Uint32(rw[0:4])
		out = append(out, TCPConnection{
			Proto:      "tcp",
			State:      tcpState(state),
			LocalAddr:  net.IP(rw[4:8]).String(),
			LocalPort:  portFromDword(binary.LittleEndian.Uint32(rw[8:12])),
			RemoteAddr: net.IP(rw[12:16]).String(),
			RemotePort: portFromDword(binary.LittleEndian.Uint32(rw[16:20])),
			PID:        binary.LittleEndian.Uint32(rw[20:24]),
		})
	}

	buf, err = extendedTCPTable(afInet6)
	if err != nil {
		return out, err
	}
	n = binary.LittleEndian.Uint32(buf[0:4])
	const row6 = 56
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*row6
		if off+row6 > len(buf) {
			break
		}
		rw := buf[off : off+row6]
		local := make(net.IP, 16)
		remote := make(net.IP, 16)
		copy(local, rw[0:16])
		copy(remote, rw[24:40])
		out = append(out, TCPConnection{
			Proto:      "tcp6",
			LocalAddr:  local.String(),
			LocalPort:  portFromDword(binary.LittleEndian.Uint32(rw[20:24])),
			RemoteAddr: remote.String(),
			RemotePort: portFromDword(binary.LittleEndian.Uint32(rw[44:48])),
			State:      tcpState(binary.LittleEndian.Uint32(rw[48:52])),
			PID:        binary.LittleEndian.Uint32(rw[52:56]),
		})
	}
	return out, nil
}

// ---- LSA user rights ------------------------------------------------------

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

const (
	policyViewLocalInformation = 0x00000001
	policyLookupNames          = 0x00000800
	statusNoMoreEntries        = 0x8000001A
)

func ntError(status uintptr) error {
	r, _, _ := procLsaNtStatusToWinError.Call(status)
	return windows.Errno(r)
}

// accountsWithRight lists the accounts that hold a user right, e.g.
// SeLockMemoryPrivilege ("Lock pages in memory"). Requires administrator.
func accountsWithRight(right string) ([]string, error) {
	var attrs lsaObjectAttributes
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var policy uintptr
	st, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)),
		policyViewLocalInformation|policyLookupNames, uintptr(unsafe.Pointer(&policy)))
	if st != 0 {
		return nil, fmt.Errorf("LsaOpenPolicy: %w", ntError(st))
	}
	defer procLsaClose.Call(policy) //nolint:errcheck

	u16, err := windows.UTF16FromString(right)
	if err != nil {
		return nil, err
	}
	name := lsaUnicodeString{
		Length:        uint16((len(u16) - 1) * 2),
		MaximumLength: uint16(len(u16) * 2),
		Buffer:        &u16[0],
	}
	var buf unsafe.Pointer
	var count uint32
	st, _, _ = procLsaEnumerateAccountsWithUserRight.Call(policy,
		uintptr(unsafe.Pointer(&name)), uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&count)))
	if st == statusNoMoreEntries {
		return []string{}, nil
	}
	if st != 0 {
		return nil, fmt.Errorf("LsaEnumerateAccountsWithUserRight: %w", ntError(st))
	}
	defer procLsaFreeMemory.Call(uintptr(buf)) //nolint:errcheck

	// buf points to an array of LSA_ENUMERATION_INFORMATION, a struct with
	// a single PSID member.
	sids := unsafe.Slice((**windows.SID)(buf), count)
	out := make([]string, 0, count)
	for _, sid := range sids {
		out = append(out, sidName(sid))
	}
	return out, nil
}

func sidName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// processUser returns DOMAIN\user owning a process, or "" when the process
// can't be opened (other users' processes need administrator rights).
func processUser(pid uint32) string {
	if pid == 0 || pid == 4 {
		return `NT AUTHORITY\SYSTEM`
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h) //nolint:errcheck
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return sidName(tu.User.Sid)
}

// ---- PDH performance counters --------------------------------------------

const (
	pdhFmtDouble   = 0x00000200
	pdhFmtNoCap100 = 0x00008000
)

type pdhFmtCounterValueDouble struct {
	CStatus uint32
	_       uint32
	Value   float64
}

type pdhQuery struct {
	handle   uintptr
	counters []uintptr
}

// newPDHQuery adds counters by their English names, which works on every
// display language of Windows.
func newPDHQuery(paths []string) (*pdhQuery, error) {
	if err := procPdhOpenQueryW.Find(); err != nil {
		return nil, err
	}
	q := &pdhQuery{}
	r, _, _ := procPdhOpenQueryW.Call(0, 0, uintptr(unsafe.Pointer(&q.handle)))
	if r != 0 {
		return nil, fmt.Errorf("PdhOpenQuery: 0x%08x", r)
	}
	for _, p := range paths {
		ptr, err := windows.UTF16PtrFromString(p)
		if err != nil {
			q.close()
			return nil, err
		}
		var c uintptr
		r, _, _ := procPdhAddEnglishCounterW.Call(q.handle, uintptr(unsafe.Pointer(ptr)), 0, uintptr(unsafe.Pointer(&c)))
		if r != 0 {
			q.close()
			return nil, fmt.Errorf("PdhAddEnglishCounter(%s): 0x%08x (performance counters may be disabled or corrupted; 'lodctr /R' rebuilds them)", p, r)
		}
		q.counters = append(q.counters, c)
	}
	return q, nil
}

func (q *pdhQuery) collect() error {
	r, _, _ := procPdhCollectQueryData.Call(q.handle)
	if r != 0 {
		return fmt.Errorf("PdhCollectQueryData: 0x%08x", r)
	}
	return nil
}

func (q *pdhQuery) values() []float64 {
	out := make([]float64, len(q.counters))
	for i, c := range q.counters {
		var v pdhFmtCounterValueDouble
		r, _, _ := procPdhGetFormattedCounterValue.Call(c, pdhFmtDouble|pdhFmtNoCap100, 0, uintptr(unsafe.Pointer(&v)))
		if r == 0 && (v.CStatus == 0 || v.CStatus == 1) {
			out[i] = v.Value
		}
	}
	return out
}

func (q *pdhQuery) close() {
	if q.handle != 0 {
		procPdhCloseQuery.Call(q.handle) //nolint:errcheck
		q.handle = 0
	}
}
