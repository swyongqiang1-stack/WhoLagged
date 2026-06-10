using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace StutterFix;

class Program
{
    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        if (!IsAdministrator())
        {
            Console.WriteLine("Please run as Administrator (right-click -> Run as Administrator)");
            Console.ReadKey();
            return;
        }

        Console.WriteLine("===== StutterFix - Find what's causing lag =====");
        Console.WriteLine("Analyzing... Please wait 10 seconds (keep your PC in laggy state).");
        Console.WriteLine("Press Ctrl+C to cancel early.");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
            Console.WriteLine("\nCancelling...");
        };

        try
        {
            var data = await CollectKernelDataAsync(TimeSpan.FromSeconds(10), cts.Token);
            var conclusion = Analyze(data);
            Console.WriteLine("\n===== DIAGNOSIS =====");
            Console.WriteLine(conclusion);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("\nSampling cancelled.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nERROR: {ex.Message}");
            Console.WriteLine("Close other performance tools (LatencyMon, WPR, etc.) and try again.");
        }

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    // 枚举已加载驱动（通过 P/Invoke）
    private static List<(ulong Base, ulong End, string Name)> EnumerateLoadedDrivers()
    {
        var result = new List<(ulong, ulong, string)>();
        const int arraySize = 1024;
        IntPtr[] imageBaseArray = new IntPtr[arraySize];
        int bytesNeeded = 0;

        if (!NativeMethods.EnumDeviceDrivers(imageBaseArray, arraySize * IntPtr.Size, ref bytesNeeded))
            return result;

        int driverCount = bytesNeeded / IntPtr.Size;
        for (int i = 0; i < driverCount; i++)
        {
            IntPtr baseAddr = imageBaseArray[i];
            byte[] fileNameBuffer = new byte[1024];
            if (NativeMethods.GetDeviceDriverFileName(baseAddr, fileNameBuffer, fileNameBuffer.Length) && fileNameBuffer[0] != 0)
            {
                string fullPath = System.Text.Encoding.ASCII.GetString(fileNameBuffer).TrimEnd('\0');
                string driverName = Path.GetFileName(fullPath);
                // 获取驱动大小（需要另外 API，暂用 0 表示，后续可通过 module load 事件补充）
                // 这里简单起见，大小设为0，地址范围只有基址，无法精确匹配；但我们会优先使用模块加载事件，
                // 枚举的驱动作为后备映射（只用于没有 ImageLoad 事件的老驱动）。
                // 更精确的大小可通过 NtQuerySystemInformation 或 GetDeviceDriverBaseName 配合读取 PE 头，但复杂度高。
                // 为简化，我们只在地址比较时使用基址匹配，不比较大小，并接受可能的误匹配（概率低）。
                result.Add(((ulong)baseAddr, 0, driverName));
            }
        }
        return result;
    }

    private static async Task<KernelData> CollectKernelDataAsync(TimeSpan duration, CancellationToken token)
    {
        var data = new KernelData();
        TraceEventSession? session = null;

        // 采集前枚举已加载驱动（作为初始映射）
        var preloadedDrivers = EnumerateLoadedDrivers();
        // 构建驱动地址映射列表（基址 -> 驱动名），稍后会与模块加载事件合并
        var driverMappings = new List<(ulong Base, ulong End, string Name)>();
        foreach (var drv in preloadedDrivers)
        {
            driverMappings.Add((drv.Base, drv.End, drv.Name));
        }

        try
        {
            session = new TraceEventSession(KernelTraceEventParser.KernelSessionName, TraceEventSessionOptions.Create);
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to start ETW session: {ex.Message}. Close other monitoring tools.", ex);
        }

        using (session)
        {
            // 启用内核事件（增加 Interrupt 关键词）
            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.ContextSwitch |
                KernelTraceEventParser.Keywords.DPC |
                KernelTraceEventParser.Keywords.Interrupt |
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.Thread |
                KernelTraceEventParser.Keywords.DiskIO |
                KernelTraceEventParser.Keywords.ImageLoad
            );

            var parser = new KernelTraceEventParser(session.Source);

            var processStartEvents = new List<ProcessTraceData>();
            var contextSwitchEvents = new List<ContextSwitchTraceData>();
            var dpcEvents = new List<DPCTraceData>();
            var interruptEvents = new List<InterruptTraceData>();
            var diskIOReadEvents = new List<DiskIOReadTraceData>();
            var diskIOWriteEvents = new List<DiskIOWriteTraceData>();
            var moduleLoadEvents = new List<ModuleLoadTraceData>();

            parser.ProcessStartup += evt => { lock (processStartEvents) processStartEvents.Add(evt.Clone()); };
            parser.ContextSwitch += evt => { lock (contextSwitchEvents) contextSwitchEvents.Add(evt.Clone()); };
            parser.DPC += evt => { lock (dpcEvents) dpcEvents.Add(evt.Clone()); };
            parser.Interrupt += evt => { lock (interruptEvents) interruptEvents.Add(evt.Clone()); };
            parser.DiskIORead += evt => { lock (diskIOReadEvents) diskIOReadEvents.Add(evt.Clone()); };
            parser.DiskIOWrite += evt => { lock (diskIOWriteEvents) diskIOWriteEvents.Add(evt.Clone()); };
            parser.ModuleLoad += evt => { lock (moduleLoadEvents) moduleLoadEvents.Add(evt.Clone()); };

            var processTask = Task.Run(() => session.Source.Process(), token);
            await Task.Delay(duration, token);
            session.Stop();

            try
            {
                await processTask;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: ETW processing stopped early: {ex.Message}");
            }

            // ---------- 离线处理 ----------
            // 合并模块加载事件到驱动映射（优先使用模块事件的基址和大小）
            foreach (var evt in moduleLoadEvents)
            {
                if (evt.ImageBase.HasValue && evt.ImageSize.HasValue && evt.ImageSize.Value > 0 && !string.IsNullOrEmpty(evt.ModuleName))
                {
                    ulong baseAddr = evt.ImageBase.Value;
                    ulong endAddr = baseAddr + evt.ImageSize.Value;
                    string name = Path.GetFileName(evt.ModuleName);
                    // 去重：如果已有相同基址的映射，替换（新的事件更准确）
                    int idx = driverMappings.FindIndex(m => m.Base == baseAddr);
                    if (idx >= 0)
                        driverMappings[idx] = (baseAddr, endAddr, name);
                    else
                        driverMappings.Add((baseAddr, endAddr, name));
                }
            }

            // 进程名称和路径（去重）
            var processNames = new Dictionary<int, string>();
            var processPaths = new Dictionary<int, string>();
            var seenPids = new HashSet<int>();
            foreach (var evt in processStartEvents)
            {
                int pid = evt.ProcessID;
                if (!string.IsNullOrEmpty(evt.ProcessName) && !processNames.ContainsKey(pid))
                    processNames[pid] = evt.ProcessName;

                if (!seenPids.Contains(pid))
                {
                    seenPids.Add(pid);
                    try
                    {
                        using var p = Process.GetProcessById(pid);
                        processPaths[pid] = p.MainModule?.FileName ?? "";
                    }
                    catch { }
                }
            }

            // 线程到进程映射
            var threadToProcess = new Dictionary<int, int>();
            foreach (var evt in contextSwitchEvents)
            {
                if (evt.OldThreadID > 0 && evt.OldProcessID > 0 && !threadToProcess.ContainsKey(evt.OldThreadID))
                    threadToProcess[evt.OldThreadID] = evt.OldProcessID;
                if (evt.NewThreadID > 0 && evt.NewProcessID > 0 && !threadToProcess.ContainsKey(evt.NewThreadID))
                    threadToProcess[evt.NewThreadID] = evt.NewProcessID;
            }

            // 上下文切换计数（仅统计被切出的用户态线程，排除系统进程）
            var ctxCountByThread = new Dictionary<int, long>();
            foreach (var evt in contextSwitchEvents)
            {
                int oldThread = evt.OldThreadID;
                int oldProc = evt.OldProcessID;
                if (oldThread > 0 && oldProc > 0) // 排除系统空闲线程（进程ID 0）
                {
                    if (!ctxCountByThread.ContainsKey(oldThread))
                        ctxCountByThread[oldThread] = 0;
                    ctxCountByThread[oldThread]++;
                }
            }

            // DPC 时间按驱动汇总
            var dpcTimeByModule = new Dictionary<string, long>();
            foreach (var evt in dpcEvents)
            {
                if (evt.RoutineAddress.HasValue && evt.DPCTime.HasValue)
                {
                    ulong addr = evt.RoutineAddress.Value;
                    string? driverName = null;
                    // 查找包含该地址的驱动模块（优先匹配有 End 范围的，其次只匹配基址）
                    foreach (var mapping in driverMappings)
                    {
                        if (mapping.End > 0)
                        {
                            if (addr >= mapping.Base && addr < mapping.End)
                            {
                                driverName = mapping.Name;
                                break;
                            }
                        }
                        else
                        {
                            // 没有大小信息，只能匹配基址相等（不精确，但作为后备）
                            if (addr == mapping.Base)
                            {
                                driverName = mapping.Name;
                                break;
                            }
                        }
                    }
                    if (driverName != null)
                    {
                        long ns = (long)evt.DPCTime.Value;
                        if (!dpcTimeByModule.ContainsKey(driverName))
                            dpcTimeByModule[driverName] = 0;
                        dpcTimeByModule[driverName] += ns;
                    }
                }
            }

            // 中断时间按驱动汇总（可选）
            var interruptTimeByModule = new Dictionary<string, double>();
            foreach (var evt in interruptEvents)
            {
                if (evt.RoutineAddress.HasValue && evt.InterruptTime.HasValue)
                {
                    ulong addr = evt.RoutineAddress.Value;
                    string? driverName = null;
                    foreach (var mapping in driverMappings)
                    {
                        if (mapping.End > 0)
                        {
                            if (addr >= mapping.Base && addr < mapping.End)
                            {
                                driverName = mapping.Name;
                                break;
                            }
                        }
                        else if (addr == mapping.Base)
                        {
                            driverName = mapping.Name;
                            break;
                        }
                    }
                    if (driverName != null)
                    {
                        if (!interruptTimeByModule.ContainsKey(driverName))
                            interruptTimeByModule[driverName] = 0;
                        interruptTimeByModule[driverName] += evt.InterruptTime.Value;
                    }
                }
            }

            // 磁盘 I/O 总延迟（使用 double 累积）
            var diskTotalLatencyMs = new Dictionary<int, double>();
            foreach (var evt in diskIOReadEvents)
            {
                if (evt.ProcessID > 0 && evt.ElapsedTimeMSec.HasValue && evt.ElapsedTimeMSec.Value > 5)
                {
                    if (!diskTotalLatencyMs.ContainsKey(evt.ProcessID))
                        diskTotalLatencyMs[evt.ProcessID] = 0;
                    diskTotalLatencyMs[evt.ProcessID] += evt.ElapsedTimeMSec.Value;
                }
            }
            foreach (var evt in diskIOWriteEvents)
            {
                if (evt.ProcessID > 0 && evt.ElapsedTimeMSec.HasValue && evt.ElapsedTimeMSec.Value > 5)
                {
                    if (!diskTotalLatencyMs.ContainsKey(evt.ProcessID))
                        diskTotalLatencyMs[evt.ProcessID] = 0;
                    diskTotalLatencyMs[evt.ProcessID] += evt.ElapsedTimeMSec.Value;
                }
            }

            data.ProcessNames = processNames;
            data.ProcessPaths = processPaths;
            data.ThreadToProcess = threadToProcess;
            data.ContextSwitchCountByThread = ctxCountByThread;
            data.DPCTimeByModule = dpcTimeByModule;
            data.InterruptTimeByModule = interruptTimeByModule;
            data.DiskIOTotalLatencyMs = diskTotalLatencyMs;
            data.CollectionDurationMs = (long)duration.TotalMilliseconds;
        }

        return data;
    }

    private static string Analyze(KernelData data)
    {
        double durationSec = data.CollectionDurationMs / 1000.0;

        // 聚合上下文切换到进程
        var ctxByProcess = new Dictionary<int, long>();
        foreach (var kv in data.ContextSwitchCountByThread)
        {
            if (data.ThreadToProcess.TryGetValue(kv.Key, out int pid))
            {
                if (!ctxByProcess.ContainsKey(pid))
                    ctxByProcess[pid] = 0;
                ctxByProcess[pid] += kv.Value;
            }
        }

        int topCtxPid = 0;
        double topCtxRate = 0;
        foreach (var kv in ctxByProcess)
        {
            double rate = kv.Value / durationSec;
            if (rate > topCtxRate)
            {
                topCtxRate = rate;
                topCtxPid = kv.Key;
            }
        }

        // DPC
        string topDpcModule = "";
        long topDpcTime = 0;
        foreach (var kv in data.DPCTimeByModule)
        {
            if (kv.Value > topDpcTime)
            {
                topDpcTime = kv.Value;
                topDpcModule = kv.Key;
            }
        }

        // Interrupt（可选，如果DPC没找到但中断很高则用）
        string topIntModule = "";
        double topIntTime = 0;
        foreach (var kv in data.InterruptTimeByModule)
        {
            if (kv.Value > topIntTime)
            {
                topIntTime = kv.Value;
                topIntModule = kv.Key;
            }
        }

        // 磁盘总延迟
        int topDiskPid = 0;
        double topDiskLatencyMs = 0;
        foreach (var kv in data.DiskIOTotalLatencyMs)
        {
            if (kv.Value > topDiskLatencyMs)
            {
                topDiskLatencyMs = kv.Value;
                topDiskPid = kv.Key;
            }
        }

        string GetProcessDesc(int pid)
        {
            if (pid <= 0) return "System Idle";
            if (pid == 4) return "System Process (PID 4)";
            string name = data.ProcessNames.GetValueOrDefault(pid, $"PID {pid}");
            string path = data.ProcessPaths.GetValueOrDefault(pid, "");
            if (!string.IsNullOrEmpty(path))
                return $"{name} ({path})";
            return name;
        }

        const double HighCtxRate = 5000;
        const long HighDpcNs = 50_000_000;      // 50ms in 10 sec
        const double HighIntMs = 50.0;          // 50ms in 10 sec
        const double HighDiskLatencyMs = 500.0;

        if (topCtxRate > HighCtxRate && topCtxPid != 0)
        {
            string culprit = GetProcessDesc(topCtxPid);
            return $"LAG DETECTED: \"{culprit}\" is causing excessive thread context switching ({topCtxRate:F0} switches/sec).\n→ Try closing or uninstalling this software.";
        }
        else if (topDpcTime > HighDpcNs && !string.IsNullOrEmpty(topDpcModule))
        {
            string softwareHint = MapDriverToSoftware(topDpcModule);
            return $"LAG DETECTED: Driver \"{topDpcModule}\" is causing high DPC latency (total {topDpcTime / 1_000_000:F1} ms in 10 sec).\n{softwareHint}\n→ Try updating, disabling, or uninstalling the associated software.";
        }
        else if (topIntTime > HighIntMs && !string.IsNullOrEmpty(topIntModule))
        {
            string softwareHint = MapDriverToSoftware(topIntModule);
            return $"LAG DETECTED: Driver \"{topIntModule}\" is causing high interrupt time (total {topIntTime:F1} ms in 10 sec).\n{softwareHint}\n→ Try updating, disabling, or uninstalling the associated software.";
        }
        else if (topDiskLatencyMs > HighDiskLatencyMs && topDiskPid != 0)
        {
            string culprit = GetProcessDesc(topDiskPid);
            return $"LAG DETECTED: \"{culprit}\" is causing slow disk I/O (total {topDiskLatencyMs:F0} ms of delay in 10 seconds).\n→ Check if it's scanning files or downloading. Try pausing or uninstalling it.";
        }
        else
        {
            return "No clear culprit detected in 10 seconds. Possible causes:\n- Lagging software was idle during sampling.\n- Hardware issue (thermal throttling, failing drive).\n- Multiple low-impact programs combined.\nTry running this tool again while the lag is happening.";
        }
    }

    private static string MapDriverToSoftware(string driverName)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "npcap.sys", "Likely from Npcap/Wireshark." },
            { "PROCEXP152.sys", "From Sysinternals Process Explorer." },
            { "protect.sys", "Often part of game anti-cheat or malware." },
            { "hook.sys", "Suspicious driver, possibly keylogger or cheat." },
            { "rtwlanu.sys", "Realtek wireless driver. Try updating." },
            { "nvlddmkm.sys", "NVIDIA driver. Try updating or lowering graphics." },
            { "atikmdag.sys", "AMD driver. Update recommended." }
        };
        string baseName = Path.GetFileName(driverName);
        if (map.TryGetValue(baseName, out string? desc))
            return desc;
        return $"Search online for '{baseName}' to find which software it belongs to.";
    }

    private static bool IsAdministrator()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}

class KernelData
{
    public Dictionary<int, string> ProcessNames { get; set; } = new();
    public Dictionary<int, string> ProcessPaths { get; set; } = new();
    public Dictionary<int, int> ThreadToProcess { get; set; } = new();
    public Dictionary<int, long> ContextSwitchCountByThread { get; set; } = new();
    public Dictionary<string, long> DPCTimeByModule { get; set; } = new();
    public Dictionary<string, double> InterruptTimeByModule { get; set; } = new();
    public Dictionary<int, double> DiskIOTotalLatencyMs { get; set; } = new();
    public long CollectionDurationMs { get; set; }
}

internal static class NativeMethods
{
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumDeviceDrivers(IntPtr[] lpImageBase, int cb, ref int lpcbNeeded);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetDeviceDriverFileName(IntPtr ImageBase, byte[] lpFilename, int nSize);
}
