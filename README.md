# WhoLagged

WhoLagged is a Windows diagnostic tool designed to identify the exact process or kernel driver responsible for system stuttering, input latency, audio distortion, and performance degradation.

Unlike traditional monitoring tools such as Task Manager, which only display resource usage, WhoLagged focuses on detecting the root cause of system lag at the kernel level.

## Purpose

The primary goal of WhoLagged is to answer a simple question:

What is causing my computer to lag?

In many cases, system performance issues occur even when CPU, memory, and disk usage appear normal. These issues are typically caused by low-level system behavior that is not visible in standard performance monitors.

WhoLagged is designed to identify these hidden bottlenecks by analyzing Windows kernel events.

## What It Detects

WhoLagged focuses on identifying the source of system instability, including:

- Processes causing excessive CPU context switching
- Kernel drivers generating high Deferred Procedure Call (DPC) activity
- Processes responsible for high-latency disk I/O operations
- Background services contributing to scheduling contention

## Key Capability

The core capability of WhoLagged is root cause identification.

It attempts to determine:

- Which process is disrupting CPU scheduling
- Which driver is introducing system latency
- Which component is responsible for observable stutter or lag

## Technical Approach

WhoLagged is built on Windows Event Tracing for Windows (ETW) and collects kernel-level telemetry, including:

- Context switch events
- Disk I/O latency events
- DPC (Deferred Procedure Call) activity
- Kernel image load events

All data is processed in real time and aggregated in memory to minimize overhead.

## Requirements

- Windows 10 / Windows 11 (x64)
- Administrator privileges (required for ETW kernel access)
- .NET 8 Runtime (or self-contained executable build)

## Usage

Run the executable with administrator privileges:

WhoLagged.exe

The tool will sample system behavior for a fixed period and output a diagnosis indicating the most likely cause of system lag.

## Build

Build from source:

dotnet build -c Release

Publish standalone executable:

dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

## Limitations

- Requires administrator privileges
- May conflict with other ETW-based tools such as Windows Performance Recorder (WPR) or LatencyMon
- Intended for diagnostic use only, not continuous monitoring
- Requires stable access to Windows kernel ETW providers

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

https://www.gnu.org/licenses/gpl-3.0.en.html

You are free to use, modify, and redistribute this software under the terms of GPL-3.0. Any derivative work must also remain under GPL-3.0.
