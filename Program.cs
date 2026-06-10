using System.Diagnostics;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace WhoLagged;

class Program
{
    static async Task Main()
    {
        if (TraceEventSession.IsElevated() == false)
        {
            Console.WriteLine("Please run as Administrator.");
            Console.ReadKey();
            return;
        }

        Console.WriteLine("===== WhoLagged - Find the software causing lag =====");
        Console.WriteLine("Sampling for 10 seconds... (Keep your PC in laggy state)");
        Console.WriteLine("Press Ctrl+C to cancel early.\n");

        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
            Console.WriteLine("\nCancelling...");
        };

        try
        {
            var result = await CollectAndAnalyzeAsync(TimeSpan.FromSeconds(10), cts.Token);
            Console.WriteLine("\n===== DIAGNOSIS =====");
            Console.WriteLine(result);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("\nSampling cancelled.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nERROR:\n{ex}");
            Console.WriteLine("\nTroubleshooting:");
            Console.WriteLine(" - Close LatencyMon, WPR, PerfView, Process Explorer and try again.");
            Console.WriteLine(" - Run as Administrator.");
            Console.WriteLine(" - If problem persists, reboot Windows.");
        }

        Console.WriteLine("\nPress any key to exit.");
        Console.ReadKey();
    }

    static async Task<string> CollectAndAnalyzeAsync(TimeSpan duration, CancellationToken token)
    {
        var ctxCountByProcess = new Dictionary<int, long>();
        var dpcCountByDriver = new Dictionary<string, long>();
        var diskLatencyByProcess = new Dictionary<int, double>();
        var processNames = new Dictionary<int, string>();
        var driverMap = new Dictionary<ulong, (ulong End, string Name)>();

        try
        {
            using var testSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName);
            testSession.Dispose();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "Kernel ETW session is already in use. Close other monitoring tools (LatencyMon, WPR, etc.) and try again.",
                ex
            );
        }

        using var session = new TraceEventSession(KernelTraceEventParser.KernelSessionName, TraceEventSessionOptions.Create);

        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.ContextSwitch |
            KernelTraceEventParser.Keywords.DiskIO
        );

        var parser = new KernelTraceEventParser(session.Source);

        void OnDiskIO(DiskIOTraceData evt)
        {
            if (evt.ProcessID > 0 && evt.ElapsedTimeMSec > 1.0)
            {
                diskLatencyByProcess.TryGetValue(evt.ProcessID, out double cur);
                diskLatencyByProcess[evt.ProcessID] = cur + evt.ElapsedTimeMSec;

                if (!processNames.ContainsKey(evt.ProcessID) && !string.IsNullOrEmpty(evt.ProcessName))
                    processNames[evt.ProcessID] = evt.ProcessName;
            }
        }

        parser.DiskIORead += OnDiskIO;
        parser.DiskIOWrite += OnDiskIO;

        session.Source.Dynamic.All += (TraceEvent evt) =>
        {
            if (evt.EventName == "CSwitch")
            {
                int oldPid = (int)evt.PayloadByName("OldProcessID");
                if (oldPid > 0)
                {
                    ctxCountByProcess.TryGetValue(oldPid, out long cur);
                    ctxCountByProcess[oldPid] = cur + 1;

                    if (!processNames.ContainsKey(oldPid))
                    {
                        string? name = evt.PayloadByName("ProcessName") as string;
                        if (!string.IsNullOrEmpty(name))
                            processNames[oldPid] = name;
                    }
                }
            }
        };

        var processTask = Task.Run(() => session.Source.Process(), token);

        try
        {
            await Task.Delay(duration, token);
        }
        finally
        {
            session.Stop();
            try { await processTask; } catch (OperationCanceledException) { }
        }

        double sec = duration.TotalSeconds;

        string GetProcessDescription(int pid)
        {
            if (pid == 0) return "System Idle Process";
            if (pid == 4) return "System (Kernel)";

            string name = processNames.TryGetValue(pid, out var n) ? n : $"PID {pid}";
            string path = "";

            try
            {
                using var p = Process.GetProcessById(pid);
                path = p.MainModule?.FileName ?? "";
                if (!processNames.ContainsKey(pid))
                    name = p.ProcessName;
            }
            catch { }

            return string.IsNullOrEmpty(path) ? name : $"{name} ({path})";
        }

        var topCtx = ctxCountByProcess
            .Where(kv => kv.Key != 0 && kv.Key != 4)
            .OrderByDescending(kv => kv.Value)
            .FirstOrDefault();

        if (topCtx.Key == 0 && ctxCountByProcess.Count > 0)
            topCtx = ctxCountByProcess.OrderByDescending(kv => kv.Value).First();

        double ctxRate = topCtx.Value / sec;

        var topDisk = diskLatencyByProcess
            .Where(kv => kv.Key != 0 && kv.Key != 4)
            .OrderByDescending(kv => kv.Value)
            .FirstOrDefault();

        if (topDisk.Key == 0 && diskLatencyByProcess.Count > 0)
            topDisk = diskLatencyByProcess.OrderByDescending(kv => kv.Value).First();

        double diskLatency = topDisk.Value;

        if (ctxRate > 5000 && topCtx.Key != 0 && topCtx.Key != 4)
        {
            return $"LAG DETECTED: \"{GetProcessDescription(topCtx.Key)}\" is causing {ctxRate:F0} context switches/sec.\n→ Try closing or uninstalling this software.";
        }
        else if (diskLatency > 500 && topDisk.Key != 0 && topDisk.Key != 4)
        {
            return $"LAG DETECTED: \"{GetProcessDescription(topDisk.Key)}\" is causing {diskLatency:F0} ms total disk delay.\n→ Check its disk activity or pause it.";
        }
        else
        {
            if (topCtx.Key == 4 && ctxRate > 5000)
                return $"High context switching in System process ({ctxRate:F0}/s). This may indicate a kernel or driver issue.\n→ Use LatencyMon for deeper analysis.";

            if (topDisk.Key == 4 && diskLatency > 500)
                return $"High disk latency in System process ({diskLatency:F0} ms). Kernel-mode activity may be responsible.\n→ Use Process Monitor or LatencyMon.";

            return "No clear culprit detected. Try running again while the issue is occurring.\nYou may also use LatencyMon for deeper analysis.";
        }
    }
}
