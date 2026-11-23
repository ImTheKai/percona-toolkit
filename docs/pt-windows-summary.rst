.. pt-windows-summary:

=============================
:program:`pt-windows-summary`
=============================

``pt-windows-summary`` summarizes system information on Microsoft Windows.

It is the Windows counterpart of :program:`pt-summary`: the report has the
same structure, the same section headers, the same ``name | value`` layout and
the same "fuzzy rounding" of counters, so reports from Windows and Linux
servers can be read and compared the same way. Where a Linux concept has no
Windows equivalent, the section is replaced by the closest Windows concept
(see `Differences from pt-summary`_).

``pt-windows-summary`` is a single self-contained executable. It does not need
Perl, PowerShell, WSL, Cygwin or any other runtime, and it does not install
anything. It only reads information; it doesn't change the system.

Usage
=====

.. code-block:: bat

   pt-windows-summary.exe [OPTIONS]

Run it from an elevated command prompt ("Run as administrator") for a
complete report. It also works as a standard user, but then the owners of
other users' processes, the accounts holding *Lock pages in memory* and the
Microsoft Defender exclusions can't be read; the report says so where
information is missing.

To send a report to Percona Support, redirect the output to a file:

.. code-block:: bat

   pt-windows-summary.exe > %COMPUTERNAME%-summary.txt

When ``pt-windows-summary.exe`` is started by double-clicking it in Explorer
(or with right-click, *Run as administrator*), the report is shown in the
console window and also saved to
``pt-windows-summary-<HOSTNAME>-<YYYYMMDD-HHMMSS>.txt`` next to the
executable (or on the Desktop if that folder is not writable), and the window
stays open until Enter is pressed. When the output is redirected or piped, the tool never
waits for input, so it is safe to use from scripts and scheduled tasks.

.. note::

   In Windows PowerShell 5.1, ``>`` writes UTF-16 files. Use
   ``pt-windows-summary.exe | Out-File -Encoding utf8 summary.txt``, or run the
   command from ``cmd.exe``, to get a UTF-8 file.

Supported platforms
===================

``pt-windows-summary`` runs on every Windows version that is still supported
by Microsoft and by Go (Windows 10 / Server 2016 and later), on both the
Desktop Experience and the Server Core installation options:

* Windows Server 2016, 2019, 2022 and 2025
* Windows 10 and Windows 11 (including LTSC/IoT editions)

Binaries are built for ``windows-amd64`` (x64) and ``windows-arm64``. All data
is read from language independent sources (WMI/CIM classes, Win32 APIs, the
registry and performance counters added by their English names), so the tool
works on every display language of Windows. It doesn't use ``wmic.exe``,
which is no longer installed by default on Windows 11 24H2 and Windows Server
2025.

Options
=======

``--config``
  Read this comma-separated list of config files. If specified, this must be
  the first option on the command line.

``--help``
  Show help and exit.

``--read-samples``
  Create a report from the files found in this directory, as saved by
  ``--save-samples``, instead of collecting data. This works on any
  platform, so reports can be rendered on Linux from samples collected on
  Windows.

``--save-samples``
  Save the collected data in this directory. The directory contains
  ``summary.json`` with all the raw data and ``collect.err`` with the
  errors of collectors that failed, if any.

``--sleep``
  default: 5

  How long to sample performance counters and process CPU usage, in seconds.
  This determines the number of lines in the vmstat-like section and the
  interval for the per-process ``%CPU`` values.

``--[no-]summarize-mounts``
  default: yes

  Report on mounted filesystems and disk usage.

``--[no-]summarize-network``
  default: yes

  Report on network controllers, configuration and connections.

``--[no-]summarize-processes``
  default: yes

  Report on top processes, notable services and performance counters.

``--version``
  Show version and exit.

Setting the ``PTDEBUG`` environment variable prints the progress and the
duration of every collector to STDERR.

Output
======

The report has the following sections. Sections marked with \* only exist
on Windows.

Percona Toolkit System Summary Report
  Date, host name, uptime, hardware (manufacturer, model, service tag,
  chassis), BIOS, Windows release (edition, version such as 22H2/24H2,
  Server Core), kernel build (``10.0.<build>.<UBR>``), architecture,
  virtualization (Hyper-V, Azure, VMware, KVM/QEMU, Xen, Amazon EC2, Google
  Compute Engine, VirtualBox, Nutanix), domain membership and role, time
  synchronization source, the latest installed update, pending reboots and
  whether the tool ran with administrator privileges.

Processor
  The same ``Processors``, ``Speeds``, ``Models`` and ``Caches`` lines as
  pt-summary, the active power plan (*Balanced* vs. *High performance*
  matters a lot for database latency) and the CPU cache table.

Memory
  Total, free (zeroed and free pages), available, used, commit charge, the
  standby list (the Windows file cache), the modified page list (the
  Windows equivalent of dirty pages), kernel pools, the sum of all working
  sets (``UsedRSS``), the pagefile configuration, NUMA nodes and the DIMM
  table.

Mounted Filesystems
  Size, usage, file system and options of every mounted volume, including
  volumes mounted in folders. ``Opts`` shows the allocation unit size
  (``bs=``, 64k is commonly recommended for database data volumes) and
  whether the volume is compressed, indexed by Windows Search, the boot or
  system volume, or holds a pagefile.

Filesystem Settings \*
  NTFS 8.3 short name creation and last access time updates.

Physical Disks \*
  Media type (SSD/HDD), bus type (NVMe, SAS, SATA, RAID, iSCSI, virtual...),
  size, model, firmware, logical/physical sector sizes and health. Replaces
  *Disk Schedulers And Queue Size*, which doesn't exist on Windows.

Disk Partitioning
  Disks and partitions. ``Start`` and ``End`` are in MiB, ``Size`` is in
  bytes. ``Align`` shows the largest of 1M, 64K and 4K that the partition
  offset is a multiple of, or ``NO`` for misaligned partitions.

Kernel Object Counts \*
  Handles, processes and threads. Replaces *Kernel Inode State*.

Storage Spaces Virtual Disks, Storage Spaces Pools \*
  Resiliency, size, footprint, columns, interleave, provisioning and health.
  Replaces *LVM Volumes* and *LVM Volume Groups*.

RAID Controller
  The detected RAID controller (LSI/Broadcom MegaRAID and Dell PERC, HP Smart
  Array, Adaptec/Microsemi, Intel RST/VROC, LSI SAS HBAs) and all storage
  adapters with their drivers. If the vendor's command line tool is
  installed (``storcli64``/``perccli64``, ``MegaCli64``, ``ssacli``,
  ``arcconf``), the output of its status command is included.

Network Config
  Physical network controllers, the TCP ``TIME_WAIT`` delay, the dynamic
  (ephemeral) port range, the congestion control provider and receive window
  auto-tuning.

Interface Statistics
  Fuzzy rounded received and transmitted bytes, packets and errors per
  network adapter.

Network Devices
  Speed, duplex, status, MTU and MAC address of every network adapter.

Network Connections
  The same fuzzy rounded summaries as pt-summary (connections by remote IP
  address, by local IP address, the top 10 local ports and the connection
  states), for IPv4 and IPv6, plus the listening ports with the name of the
  process that owns them.

Top Processes, Top Processes By Memory
  The 10 busiest processes by CPU during the ``--sleep`` interval and the
  10 largest by working set. ``%CPU`` is relative to one logical CPU, as in
  ``top``. ``RES`` is the working set, ``PRIV`` the private bytes (commit).

Notable Processes
  The OpenSSH server, database and database tooling services (MySQL,
  MariaDB, Percona Server, PostgreSQL, MongoDB, ProxySQL, HAProxy, PMM,
  SQL Server, Redis...) and security software (Microsoft Defender and common
  third-party antivirus/EDR products), with their state, start mode and
  executable path. Command line arguments are never collected, because they
  may contain credentials.

Simplified and fuzzy rounded vmstat (wait please)
  One line per second, from Windows performance counters: processor queue
  length (``r``), disk queue length (``dq``), pages read from and written to
  disk per second (``pi``/``po``), disk reads and writes in KB/s
  (``bi``/``bo``), interrupts (``in``) and context switches (``cs``) per
  second, and user, privileged, idle and interrupt+DPC CPU percentages.

Memory management
  The large page size and the accounts holding the *Lock pages in memory*
  privilege (``SeLockMemoryPrivilege``), needed for large pages in MySQL
  (``large-pages``) and for locked buffer pools. Replaces the transparent
  huge pages check.

Security \*
  Microsoft Defender antivirus state and its path and process exclusions
  (antivirus scanning of database files is a common cause of performance
  problems), and the state of the Windows Firewall profiles.

Collection Errors \*
  Collectors that failed or timed out. Every collector runs with a timeout,
  so a hanging WMI provider can't block the report.

Differences from pt-summary
===========================

============================================  ==========================================
pt-summary (Linux)                            pt-windows-summary
============================================  ==========================================
``Threading``, ``Compiler``, ``SELinux``      not applicable, not shown
``Disk Schedulers And Queue Size``            ``Physical Disks``
``Kernel Inode State``                        ``Kernel Object Counts``
``LVM Volumes``, ``LVM Volume Groups``        ``Storage Spaces Virtual Disks``/``Pools``
``Swappiness``, ``DirtyPolicy``               ``Pagefile``, ``Dirty`` (modified list)
``FIN Timeout``                               ``TIME_WAIT`` (``TcpTimedWaitDelay``)
``Notable Processes`` (sshd, OOM -17)         sshd, database and security services
vmstat ``b``, ``si``/``so``, ``wa``/``st``    ``dq``, ``pi``/``po``, ``hi``
Transparent huge pages                        Large pages, *Lock pages in memory*
============================================  ==========================================

Authors
=======

Percona

Copyright, License, and Warranty
================================

This program is copyright 2026 Percona LLC and/or its affiliates.

THIS PROGRAM IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 2; OR the Perl Artistic License.  On UNIX and similar
systems, you can issue \`man perlgpl' or \`man perlartistic' to read these
licenses.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place, Suite 330, Boston, MA  02111-1307  USA.

VERSION
=======

:program:`pt-windows-summary` 3.7.2
