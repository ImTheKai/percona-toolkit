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

// A small WMI/CIM query helper built directly on go-ole.
//
// We deliberately don't use a typed WMI library:
//   - Typed libraries fail a whole query when a struct field is missing from a
//     class. Property sets differ between Windows 10/11 and Server 2016-2025,
//     so every row here is read generically and a missing property simply
//     reads as absent.
//   - Common libraries serialize all queries with a global mutex. A single
//     hung WMI provider (a frequent problem on unhealthy servers) would then
//     block every other collector. Here each query runs on its own locked OS
//     thread with its own COM apartment, so the collector runner can time out
//     one collector and continue with the rest.
//   - We never shell out to wmic.exe: it is deprecated and no longer installed
//     by default on Windows 11 24H2 and Windows Server 2025.

import (
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

const (
	nsCIMV2    = `root\CIMV2`
	nsStorage  = `root\Microsoft\Windows\Storage`
	nsStdCIMV2 = `root\StandardCimv2`
	nsDefender = `root\Microsoft\Windows\Defender`
	nsPower    = `root\CIMV2\power`

	wbemFlagReturnImmediately = 0x10
	wbemFlagForwardOnly       = 0x20

	cimSint64   = 20
	cimUint64   = 21
	cimDatetime = 101
)

type wmiRow map[string]interface{}

func wmiQuery(namespace, query string) (rows []wmiRow, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		oleErr, ok := err.(*ole.OleError)
		// S_FALSE (1): COM was already initialized on this thread.
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			return nil, fmt.Errorf("CoInitializeEx: %w", err)
		}
	}
	defer ole.CoUninitialize()

	defer func() {
		// go-ole can panic on unexpected VARIANT types. Never let a single
		// odd property bring down the whole report.
		if r := recover(); r != nil {
			err = fmt.Errorf("WMI query %q panicked: %v", query, r)
		}
	}()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, fmt.Errorf("cannot create SWbemLocator: %w", err)
	}
	defer unknown.Release()

	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	defer locator.Release()

	serviceRaw, err := oleutil.CallMethod(locator, "ConnectServer", nil, namespace)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to WMI namespace %s: %w", namespace, err)
	}
	service := serviceRaw.ToIDispatch()
	defer serviceRaw.Clear()

	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", query, "WQL",
		wbemFlagReturnImmediately|wbemFlagForwardOnly)
	if err != nil {
		return nil, fmt.Errorf("WMI query %q failed: %w", query, err)
	}
	result := resultRaw.ToIDispatch()
	defer resultRaw.Clear()

	props := selectedProperties(query)
	err = forEach(result, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		var row wmiRow
		var err error
		if props != nil {
			row = readProperties(item, props)
		} else {
			row, err = readObject(item)
		}
		if err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		return rows, fmt.Errorf("WMI query %q: %w", query, err)
	}
	return rows, nil
}

// forEach iterates an enumerable COM collection.
func forEach(coll *ole.IDispatch, f func(v *ole.VARIANT) error) error {
	enumProp, err := coll.GetProperty("_NewEnum")
	if err != nil {
		return err
	}
	defer enumProp.Clear()
	enum, err := enumProp.ToIUnknown().IEnumVARIANT(ole.IID_IEnumVariant)
	if err != nil {
		return err
	}
	if enum == nil {
		return fmt.Errorf("cannot enumerate collection")
	}
	defer enum.Release()

	for {
		item, n, err := enum.Next(1)
		// At the end of the collection Next returns S_FALSE, which go-ole
		// reports as an error, together with n == 0. Check n first.
		if n == 0 {
			return nil
		}
		if err != nil {
			return err
		}
		ferr := f(&item)
		item.Clear()
		if ferr != nil {
			return ferr
		}
	}
}

var selectRe = regexp.MustCompile(`(?is)^\s*select\s+(.+?)\s+from\s`)

// selectedProperties returns the property names of a "SELECT a, b FROM"
// query, or nil for "SELECT *".
func selectedProperties(query string) []string {
	m := selectRe.FindStringSubmatch(query)
	if m == nil || strings.TrimSpace(m[1]) == "*" {
		return nil
	}
	var props []string
	for _, p := range strings.Split(m[1], ",") {
		if p = strings.TrimSpace(p); p != "" {
			props = append(props, p)
		}
	}
	return props
}

// readProperties reads only the named properties. This is several times
// cheaper than enumerating Properties_, which matters for large classes such
// as Win32_Process. Values arrive without their CIM type, so 64-bit integers
// and datetimes are strings; the typed getters handle that.
func readProperties(obj *ole.IDispatch, props []string) wmiRow {
	row := wmiRow{}
	for _, name := range props {
		v, err := oleutil.GetProperty(obj, name)
		if err != nil {
			continue
		}
		row[name] = convertVariant(v, 0)
		v.Clear()
	}
	return row
}

func readObject(obj *ole.IDispatch) (wmiRow, error) {
	row := wmiRow{}
	propsRaw, err := oleutil.GetProperty(obj, "Properties_")
	if err != nil {
		return nil, err
	}
	defer propsRaw.Clear()
	props := propsRaw.ToIDispatch()

	err = forEach(props, func(v *ole.VARIANT) error {
		p := v.ToIDispatch()
		nameV, err := oleutil.GetProperty(p, "Name")
		if err != nil {
			return nil
		}
		name := nameV.ToString()
		nameV.Clear()

		cimType := 0
		if ctV, err := oleutil.GetProperty(p, "CIMType"); err == nil {
			cimType = int(variantInt(ctV))
			ctV.Clear()
		}

		valV, err := oleutil.GetProperty(p, "Value")
		if err != nil {
			return nil
		}
		row[name] = convertVariant(valV, cimType)
		valV.Clear()
		return nil
	})
	return row, err
}

func variantInt(v *ole.VARIANT) int64 {
	switch x := v.Value().(type) {
	case int8:
		return int64(x)
	case int16:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case uint8:
		return int64(x)
	case uint16:
		return int64(x)
	case uint32:
		return int64(x)
	case uint64:
		return int64(x)
	}
	return 0
}

func convertVariant(v *ole.VARIANT, cimType int) interface{} {
	if v.VT == ole.VT_NULL || v.VT == ole.VT_EMPTY {
		return nil
	}
	if v.VT&ole.VT_ARRAY != 0 {
		arr := v.ToArray()
		if arr == nil {
			return nil
		}
		vals := arr.ToValueArray()
		out := make([]interface{}, 0, len(vals))
		for _, x := range vals {
			out = append(out, convertScalar(x, cimType))
		}
		return out
	}
	return convertScalar(v.Value(), cimType)
}

func convertScalar(val interface{}, cimType int) interface{} {
	s, ok := val.(string)
	if !ok {
		return val
	}
	switch cimType {
	case cimUint64:
		if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			return u
		}
	case cimSint64:
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
	case cimDatetime:
		if t, ok := parseCIMDatetime(s); ok {
			return t
		}
	}
	return s
}

// parseCIMDatetime parses yyyymmddHHMMSS.mmmmmmsUUU where UUU is the UTC
// offset in minutes.
func parseCIMDatetime(s string) (time.Time, bool) {
	if len(s) != 25 || strings.Contains(s, "*") || s[21] == ':' {
		return time.Time{}, false
	}
	mins, err := strconv.Atoi(s[22:])
	if err != nil {
		return time.Time{}, false
	}
	tz := fmt.Sprintf("%c%02d%02d", s[21], mins/60, mins%60)
	t, err := time.Parse("20060102150405.000000-0700", s[:21]+tz)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// ---- typed getters -------------------------------------------------------

func (r wmiRow) str(k string) string {
	switch v := r[k].(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func (r wmiRow) u64(k string) uint64 {
	switch v := r[k].(type) {
	case uint64:
		return v
	case int64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int32:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case uint32:
		return uint64(v)
	case int16:
		return uint64(v)
	case uint16:
		return uint64(v)
	case uint8:
		return uint64(v)
	case int8:
		return uint64(v)
	case int:
		return uint64(v)
	case float64:
		return uint64(v)
	case float32:
		return uint64(v)
	case string:
		u, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		return u
	}
	return 0
}

func (r wmiRow) i(k string) int {
	switch v := r[k].(type) {
	case int64:
		return int(v)
	case int32:
		return int(v)
	case int16:
		return int(v)
	case int8:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	}
	return int(r.u64(k))
}

func (r wmiRow) b(k string) bool {
	switch v := r[k].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return r.u64(k) != 0
}

func (r wmiRow) t(k string) time.Time {
	switch v := r[k].(type) {
	case time.Time:
		return v
	case string:
		if t, ok := parseCIMDatetime(v); ok {
			return t
		}
	}
	return time.Time{}
}

func (r wmiRow) strs(k string) []string {
	arr, ok := r[k].([]interface{})
	if !ok {
		if s := r.str(k); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		} else if x != nil {
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}

func (r wmiRow) ints(k string) []int {
	arr, ok := r[k].([]interface{})
	if !ok {
		return nil
	}
	out := make([]int, 0, len(arr))
	for _, x := range arr {
		out = append(out, wmiRow{"v": x}.i("v"))
	}
	return out
}

// char16 properties (e.g. MSFT_Partition.DriveLetter) arrive as integers.
func (r wmiRow) char16(k string) string {
	switch v := r[k].(type) {
	case string:
		return strings.Trim(v, "\x00 ")
	case nil:
		return ""
	}
	n := r.u64(k)
	if n == 0 {
		return ""
	}
	return string(rune(n))
}
