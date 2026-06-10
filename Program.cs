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
            // 输出完整异常（包括 Win32Exception 等）
            Console.WriteLine($"\nFATAL ERROR:\n{ex}");
            Console.WriteLine("\n📌 Troubleshooting:");
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
        var dpcCountByDriver = new Dictionary<string, long>();      // DPC 暂未启用
        var diskLatencyByProcess = new Dictionary<int, double>();
        var processNames = new Dictionary<int, string>();
        var driverMap = new Dictionary<ulong, (ulong End, string Name)>();

        // ---------- 检测 ETW 内核会话是否被占用 ----------
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

        // 阶段 1：先启用最稳定的关键字（ContextSwitch + DiskIO）
        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.ContextSwitch |
            KernelTraceEventParser.Keywords.DiskIO
            // 阶段 2 可添加 ImageLoad
            // | KernelTraceEventParser.Keywords.ImageLoad
            // 阶段 3 可添加 DPC
            // | KernelTraceEventParser.Keywords.DeferredProcedureCalls
        );

        var parser = new KernelTraceEventParser(session.Source);

        // ---------- 模块加载（待启用 ImageLoad 关键字后生效）----------
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
        // 当前未启用 ImageLoad 关键字，暂不挂载
        // parser.ImageLoad += OnImageLoad;
        // parser.ImageDCStart += OnImageLoad;

        // ---------- 磁盘 I/O ----------
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

        // ---------- 上下文切换（动态事件）----------
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
            // DPC 事件待启用关键字后取消注释
            // else if (evt.EventName == "DPC")
            // {
            //     var routineObj = evt.PayloadByName("Routine");
            //     if (routineObj == null) return;
            //     ulong addr = Convert.ToUInt64(routineObj);
            //     if (addr == 0) return;
            //     ……
            // }
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

        // ---------- 分析 ----------
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

        // DPC 暂未采集，值均为 0
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
