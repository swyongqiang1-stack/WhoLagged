# WhoLagged

WhoLagged is a Windows diagnostic tool that identifies the process or driver responsible for system stuttering, input lag, and performance degradation.

It is designed for situations where Task Manager shows normal CPU, memory, and disk usage, but the system still feels slow or unresponsive.

## Problem It Solves

Modern Windows systems can experience stuttering even when resource usage appears normal.

Typical symptoms include:

- Mouse or keyboard input delay
- Audio crackling or distortion
- Game stuttering despite stable FPS
- Random UI freezes
- System lag with low CPU usage

These issues are often caused by kernel-level scheduling or driver behavior that is not visible in traditional monitoring tools.

## What WhoLagged Does

WhoLagged analyzes low-level system behavior to identify the most likely cause of lag, including:

- Processes causing excessive CPU scheduling pressure
- Drivers introducing kernel-level latency (DPC activity)
- Disk I/O operations causing hidden delays

It then produces a simple result pointing to the most likely culprit.

## Key Difference

Unlike Task Manager or basic performance monitors, WhoLagged focuses on root cause detection rather than resource usage.

Unlike heavy diagnostic tools such as LatencyMon, it provides a simplified and direct result.

## Output Example

The tool will output a diagnosis such as:

- A process causing excessive scheduling load
- A driver responsible for system latency
- Disk-related performance bottleneck
- Or no clear culprit detected

## Technical Approach

WhoLagged analyzes Windows kernel-level runtime behavior using event-based system telemetry.

It focuses on scheduling patterns, driver execution behavior, and I/O latency signals to detect anomalies that correlate with system stuttering.

All data is processed in real time with minimal overhead.

## Requirements

- Windows 10 / Windows 11 (x64)
- Administrator privileges
- .NET 8 Runtime

## Usage

Run the executable as Administrator:

WhoLagged.exe

The tool will sample system behavior for a short period and output a diagnosis.

## Build

dotnet build -c Release

dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

## License

GNU GPL-3.0

https://www.gnu.org/licenses/gpl-3.0.en.html
