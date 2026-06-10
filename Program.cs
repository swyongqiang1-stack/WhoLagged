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
            Console.WriteLine($"\nERROR: {ex.Message}");
            Console.WriteLine("Close other monitoring tools (LatencyMon, WPR, etc.) and try again.");
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

        using var session = new TraceEventSession(KernelTraceEventParser.KernelSessionName, TraceEventSessionOptions.Create);
        
        // 启用所有内核事件，确保 CSwitch 和 DPC 必定被捕获
        session.EnableKernelProvider(KernelTraceEventParser.Keywords.All);

        var parser = new KernelTraceEventParser(session.Source);

        // ---------- 模块加载（强类型，无问题）----------
        void OnImageLoad(ImageLoadTraceData evt)
        {
            if (evt.ImageBase == 0 || evt.ImageSize <= 0 || string.IsNullOrEmpty(evt.FileName))
                return;
            string driverName = Path.GetFileName(evt.FileName);
            if (string.IsNullOrEmpty(driverName))
                return;
            ulong end = evt.ImageBase + (ulong)evt.ImageSize;
            driverMap[evt.ImageBase] = (end, driverName);
        }
        parser.ImageLoad += OnImageLoad;
        parser.ImageDCStart += OnImageLoad;

        // ---------- 磁盘 I/O（强类型，已验证可用）----------
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

        // ---------- 上下文切换 与 DPC（使用动态事件，绕过版本 API 差异）----------
        session.Source.Dynamic.All += (TraceEvent evt) =>
        {
            // 只处理我们需要的事件，忽略其他（包括已强类型处理的 DiskIO）
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
            else if (evt.EventName == "DPC")
            {
                ulong addr = (ulong)evt.PayloadByName("Routine");
                if (addr == 0) return;

                string? driver = null;
                foreach (var kv in driverMap)
                {
                    if (addr >= kv.Key && addr < kv.Value.End)
                    {
                        driver = kv.Value.Name;
                        break;
                    }
                }

                if (driver != null)
                {
                    dpcCountByDriver.TryGetValue(driver, out long cur);
                    dpcCountByDriver[driver] = cur + 1;
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

        // ---------- 分析逻辑（与之前完全相同）----------
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

        var topDpc = dpcCountByDriver.OrderByDescending(kv => kv.Value).FirstOrDefault();
        double dpcRate = topDpc.Value / sec;

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
        else if (dpcRate > 3000 && topDpc.Value > 0)
        {
            return $"LAG DETECTED: Driver \"{topDpc.Key}\" is causing {dpcRate:F0} DPCs/sec.\n→ Update, disable, or uninstall the associated device/software.";
        }
        else if (diskLatency > 500 && topDisk.Key != 0 && topDisk.Key != 4)
        {
            return $"LAG DETECTED: \"{GetProcessDescription(topDisk.Key)}\" is causing {diskLatency:F0} ms total disk delay.\n→ Check its disk activity or pause it.";
        }
        else
        {
            if (topCtx.Key == 4 && ctxRate > 5000)
                return $"High context switching in System process ({ctxRate:F0}/s). This often indicates a kernel/driver issue.\n→ Use LatencyMon to identify the offending driver.";
            if (topDisk.Key == 4 && diskLatency > 500)
                return $"High disk latency in System process ({diskLatency:F0} ms). Kernel-mode activities may be responsible.\n→ Use Process Monitor or LatencyMon for deeper analysis.";
            return "No clear culprit detected. Try running again while lag is happening.\nYou may also use LatencyMon for deeper driver analysis.";
        }
    }
}
