using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;

namespace ZentriScanner
{

    public class ClientsDatabase
    {
        [JsonPropertyName("clients")]
        public List<ClientDef> Clients { get; set; } = new();
    }

    public class ClientDef
    {
        [JsonPropertyName("name")]        public string Name        { get; set; } = "";
        [JsonPropertyName("description")] public string Description { get; set; } = "";
        [JsonPropertyName("color")]       public string Color       { get; set; } = "White";
        [JsonPropertyName("signatures")]  public List<string> Signatures { get; set; } = new();
    }


    public class Detection
    {
        public int    Pid          { get; set; }
        public string ProcessName  { get; set; } = "";
        public string ClientName   { get; set; } = "";
        public string Description  { get; set; } = "";
        public string Color        { get; set; } = "White";
        public List<string> MatchedSignatures { get; set; } = new();
    }


    internal static class WinApi
    {
        public const int PROCESS_VM_READ           = 0x0010;
        public const int PROCESS_QUERY_INFORMATION = 0x0400;

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess, IntPtr lpBase,
            byte[] buf, int size, out int read);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(
            IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr  BaseAddress;
            public IntPtr  AllocationBase;
            public uint    AllocationProtect;
            public IntPtr  RegionSize;
            public uint    State;
            public uint    Protect;
            public uint    Type;
        }

        public const uint MEM_COMMIT  = 0x1000;
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_GUARD    = 0x100;
    }


    internal static class Program
    {
        private const int CHUNK = 4 * 1024 * 1024;

        private const int MIN_STR_LEN = 6;


        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            PrintBanner();

            bool saveReport = args.Contains("--report") || args.Contains("-r");
            bool verbose    = args.Contains("--verbose") || args.Contains("-v");
            bool doomsday   = args.Contains("--doomsday") || args.Contains("-d");
            bool fullScan   = args.Contains("--full") || args.Contains("-f");

            string? targetJar = args.FirstOrDefault(a => 
                a.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) ||
                (File.Exists(a) && !a.StartsWith("-")));

            if (doomsday)
            {
                if (!string.IsNullOrEmpty(targetJar))
                {
                    AnalyzeSingleJar(targetJar, verbose);
                }
                else
                {
                    RunDoomsdayScan(verbose, saveReport);
                }
                PressAnyKey();
                return;
            }

            var db = LoadDatabase();
            if (db == null || db.Clients.Count == 0)
            {
                Warn("Clients.json NOT found !!!.");
                return;
            }

            Info($"Clients database loaded: {db.Clients.Count} known clients.");
            Console.WriteLine();

            var javaProcs = GetJavaProcesses();

            if (javaProcs.Count == 0)
            {
                Warn("No se encontraron procesos java/javaw activos.");
                PressAnyKey();
                return;
            }

            Info($"Procesos java encontrados: {javaProcs.Count}");
            Console.WriteLine();

            var detections = new List<Detection>();
            int totalScanned = 0;

            foreach (var proc in javaProcs)
            {
                totalScanned++;
                Console.Write($"  [{totalScanned}/{javaProcs.Count}] Escaneando ");
                WriteColor($"PID {proc.Id}", ConsoleColor.Cyan);
                Console.Write($" ({proc.ProcessName}) ... ");

                try
                {
                    var found = ScanProcess(proc, db.Clients, verbose);
                    if (found.Count > 0)
                    {
                        WriteColorLine("coocked", ConsoleColor.Red);
                        detections.AddRange(found);
                    }
                    else
                    {
                        WriteColorLine("Clean", ConsoleColor.Green);
                    }
                }
                catch (Exception ex)
                {
                    WriteColorLine($"Error: {ex.Message}", ConsoleColor.DarkYellow);
                }
            }

            Console.WriteLine();
            PrintResults(detections);

            if (saveReport)
                SaveReport(detections, db.Clients.Count, totalScanned);

            PressAnyKey();
        }


        static ClientsDatabase? LoadDatabase()
        {
            var paths = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "clients.json"),
                "clients.json"
            };

            foreach (var p in paths)
            {
                if (!File.Exists(p)) continue;
                try
                {
                    var json = File.ReadAllText(p);
                    return JsonSerializer.Deserialize<ClientsDatabase>(json);
                }
                catch (Exception ex)
                {
                    Warn($"Error leyendo {p}: {ex.Message}");
                }
            }

            Warn("clients.json no encontrado. Se ejecuta el finder junto a su clients.json");
            return null;
        }


        static List<Process> GetJavaProcesses()
        {
            var result = new List<Process>();
            foreach (var p in Process.GetProcesses())
            {
                if (p.ProcessName.Equals("java",   StringComparison.OrdinalIgnoreCase) ||
                    p.ProcessName.Equals("javaw",  StringComparison.OrdinalIgnoreCase) ||
                    p.ProcessName.Equals("javaws", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(p);
                }
            }
            return result;
        }


        static List<Detection> ScanProcess(Process proc, List<ClientDef> clients, bool verbose)
        {
            IntPtr hProcess = WinApi.OpenProcess(
                WinApi.PROCESS_VM_READ | WinApi.PROCESS_QUERY_INFORMATION,
                false, proc.Id);

            if (hProcess == IntPtr.Zero)
                throw new Exception("Sin permisos. Ejecuta como Administrador.");

            try
            {
                var hits = new Dictionary<int, HashSet<string>>();
                for (int i = 0; i < clients.Count; i++)
                    hits[i] = new HashSet<string>(StringComparer.Ordinal);

                IntPtr addr = IntPtr.Zero;
                uint mbiSize = (uint)Marshal.SizeOf<WinApi.MEMORY_BASIC_INFORMATION>();

                while (true)
                {
                    int r = WinApi.VirtualQueryEx(hProcess, addr, out var mbi, mbiSize);
                    if (r == 0) break;

                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    bool readable = mbi.State == WinApi.MEM_COMMIT
                                 && (mbi.Protect & WinApi.PAGE_NOACCESS) == 0
                                 && (mbi.Protect & WinApi.PAGE_GUARD) == 0;

                    if (readable)
                    {
                        long offset = 0;
                        while (offset < regionSize)
                        {
                            int toRead = (int)Math.Min(CHUNK, regionSize - offset);
                            byte[] buf = new byte[toRead];
                            bool ok = WinApi.ReadProcessMemory(
                                hProcess,
                                IntPtr.Add(mbi.BaseAddress, (int)offset),
                                buf, toRead, out int bytesRead);

                            if (ok && bytesRead > 0)
                                SearchBuffer(buf, bytesRead, clients, hits);

                            offset += toRead;
                        }
                    }

                    try
                    {
                        addr = IntPtr.Add(mbi.BaseAddress, (int)Math.Min(regionSize, int.MaxValue));
                    }
                    catch { break; }

                    if ((ulong)addr.ToInt64() >= 0x7FFFFFFFFFFF) break;
                }

                var detections = new List<Detection>();
                for (int i = 0; i < clients.Count; i++)
                {
                    if (hits[i].Count == 0) continue;

                    detections.Add(new Detection
                    {
                        Pid         = proc.Id,
                        ProcessName = proc.ProcessName,
                        ClientName  = clients[i].Name,
                        Description = clients[i].Description,
                        Color       = clients[i].Color,
                        MatchedSignatures = hits[i].ToList()
                    });
                }

                return detections;
            }
            finally
            {
                WinApi.CloseHandle(hProcess);
            }
        }


        static void SearchBuffer(byte[] buf, int len,
                                 List<ClientDef> clients,
                                 Dictionary<int, HashSet<string>> hits)
        {
            int start = -1;
            for (int i = 0; i <= len; i++)
            {
                bool printable = i < len && buf[i] >= 0x20 && buf[i] < 0x7F;

                if (printable)
                {
                    if (start < 0) start = i;
                }
                else
                {
                    if (start >= 0)
                    {
                        int runLen = i - start;
                        if (runLen >= MIN_STR_LEN)
                        {
                            string s = Encoding.ASCII.GetString(buf, start, runLen);
                            MatchSignatures(s, clients, hits);
                        }
                        start = -1;
                    }
                }
            }
        }


        static void MatchSignatures(string s,
                                    List<ClientDef> clients,
                                    Dictionary<int, HashSet<string>> hits)
        {
            for (int i = 0; i < clients.Count; i++)
            {
                foreach (var sig in clients[i].Signatures)
                {
                    if (s.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        hits[i].Add(sig);
                    }
                }
            }
        }


        static void PrintResults(List<Detection> detections)
        {
            Console.WriteLine(new string('═', 60));

            if (detections.Count == 0)
            {
                WriteColorLine("    Sin detecciones. Procesos limpios.", ConsoleColor.Green);
                Console.WriteLine(new string('═', 60));
                return;
            }

            WriteColorLine($"    {detections.Count} Hacks clients detecteds", ConsoleColor.Red);
            Console.WriteLine(new string('═', 60));
            Console.WriteLine();

            foreach (var d in detections)
            {
                WriteColor("  ● Cliente: ", ConsoleColor.White);
                WriteColorLine(d.ClientName, ParseColor(d.Color));

                Console.Write("    Descripción : "); Console.WriteLine(d.Description);
                Console.Write("    PID          : "); WriteColorLine(d.Pid.ToString(), ConsoleColor.Cyan);
                Console.Write("    Proceso      : "); Console.WriteLine(d.ProcessName);

                Console.WriteLine("    Firmas match:");
                foreach (var sig in d.MatchedSignatures)
                    WriteColorLine($"      → {sig}", ConsoleColor.Yellow);

                Console.WriteLine();
            }
        }


        static void SaveReport(List<Detection> detections, int totalClients, int totalProcs)
        {
            string filename = $"ZentriScanner_report_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            var sb = new StringBuilder();

            sb.AppendLine("══════════════════════════════════════════════════════════");
            sb.AppendLine("  ZentriScanner - Screenshare Cheat Detector - REPORTE");
            sb.AppendLine($"  Fecha    : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"  Procesos : {totalProcs}   Clientes DB: {totalClients}");
            sb.AppendLine("══════════════════════════════════════════════════════════");
            sb.AppendLine();

            if (detections.Count == 0)
            {
                sb.AppendLine("  SIN DETECCIONES — procesos limpios.");
            }
            else
            {
                sb.AppendLine($"  DETECCIONES: {detections.Count}");
                sb.AppendLine();
                foreach (var d in detections)
                {
                    sb.AppendLine($"  Cliente  : {d.ClientName}");
                    sb.AppendLine($"  Desc.    : {d.Description}");
                    sb.AppendLine($"  PID      : {d.Pid}");
                    sb.AppendLine($"  Proceso  : {d.ProcessName}");
                    sb.AppendLine("  Firmas   :");
                    foreach (var sig in d.MatchedSignatures)
                        sb.AppendLine($"    -> {sig}");
                    sb.AppendLine();
                }
            }

            File.WriteAllText(filename, sb.ToString());
            Info($"Reporte guardado en: {filename}");
        }


        static ConsoleColor ParseColor(string name) =>
            Enum.TryParse<ConsoleColor>(name, true, out var c) ? c : ConsoleColor.White;

        static void WriteColor(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ResetColor();
        }

        static void WriteColorLine(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }

        static void Info(string msg)
        {
            Console.Write("  ");
            WriteColor("[INFO] ", ConsoleColor.Cyan);
            Console.WriteLine(msg);
        }

        static void Warn(string msg)
        {
            Console.Write("  ");
            WriteColor("[WARN] ", ConsoleColor.Yellow);
            Console.WriteLine(msg);
        }

        static void PressAnyKey()
        {
            Console.WriteLine();
            WriteColor("  Presiona cualquier tecla para salir...", ConsoleColor.DarkGray);
            Console.ReadKey(true);
            Console.WriteLine();
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"
   _____ _____ _______          _ 
  / ____/ ____|__   __|        | |
 | (___| (___    | | ___   ___ | |
  \___ \\___ \   | |/ _ \ / _ \| |
  ____) |___) |  | | (_) | (_) | |
 |_____/_____/   |_|\___/ \___/|_|");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("        Screenshare Cheat Detector v3.0");
            Console.WriteLine("        Wurst | Meteor | Prestige | Doomsday | ++");
            Console.ResetColor();
            Console.WriteLine();
        }

        static void RunDoomsdayScan(bool verbose, bool saveReport)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(@"
    ____                                __           
   / __ \____  ____  ____ ___  _____   / /___  __  __
  / / / / __ \/ __ \/ __ `__ \/ ___/  / / __ \/ / / /
 / /_/ / /_/ / /_/ / / / / / (__  )  / / /_/ / /_/ / 
/_____/\____/\____/_/ /_/ /_/____/  /_/\____/\__, /  
                                            /____/   
        DOOMSDAY CLIENT FORENSICS SCANNER");
            Console.ResetColor();
            Console.WriteLine();

            var result = DoomsdayDetector.RunFullScan(verbose);
            DoomsdayDetector.PrintResults(result);

            if (saveReport && result.IsDetected)
            {
                SaveDoomsdayReport(result);
            }
        }

        static void AnalyzeSingleJar(string jarPath, bool verbose)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(@"
    ____                                __           
   / __ \____  ____  ____ ___  _____   / /___  __  __
  / / / / __ \/ __ \/ __ `__ \/ ___/  / / __ \/ / / /
 / /_/ / /_/ / /_/ / / / / / (__  )  / / /_/ / /_/ / 
/_____/\____/\____/_/ /_/ /_/____/  /_/\____/\__, /  
                                            /____/   
        SINGLE JAR ANALYZER");
            Console.ResetColor();
            Console.WriteLine();

            if (!File.Exists(jarPath))
            {
                Warn($"Archivo no encontrado: {jarPath}");
                return;
            }

            Info($"Analizando: {jarPath}");
            Console.WriteLine();

            var result = DoomsdayDetector.AnalyzeJar(jarPath, verbose);

            Console.WriteLine(new string('═', 60));
            Console.WriteLine();

            if (result.IsDetected)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  ⚠ DOOMSDAY CLIENT DETECTADO");
                Console.ResetColor();
                Console.WriteLine();
                Console.WriteLine($"  Confianza: {result.Confidence}");
                Console.WriteLine($"  Byte Patterns: {result.BytePatternMatches}");
                Console.WriteLine($"  Class Matches: {result.ClassNameMatches}");
                Console.WriteLine($"  Single Letter Classes: {result.SingleLetterClasses}");
                Console.WriteLine($"  JAR Renombrado: {(result.IsRenamedJar ? "Sí" : "No")}");
                Console.WriteLine();

                if (result.MatchedPatterns.Count > 0)
                {
                    Console.WriteLine("  Patrones encontrados:");
                    foreach (var pattern in result.MatchedPatterns)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"    → {pattern}");
                        Console.ResetColor();
                    }
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✓ No se detectó Doomsday Client");
                Console.ResetColor();

                if (!string.IsNullOrEmpty(result.Error))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  Nota: {result.Error}");
                    Console.ResetColor();
                }
            }

            Console.WriteLine();
        }

        static void SaveDoomsdayReport(DoomsdayDetector.DoomsdayResult result)
        {
            string filename = $"doomsday_report_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            var sb = new StringBuilder();

            sb.AppendLine("══════════════════════════════════════════════════════════");
            sb.AppendLine("  DOOMSDAY CLIENT FORENSICS REPORT");
            sb.AppendLine($"  Fecha     : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"  Confianza : {result.Confidence}");
            sb.AppendLine("══════════════════════════════════════════════════════════");
            sb.AppendLine();

            sb.AppendLine($"  TOTAL INDICADORES: {result.Findings.Count}");
            sb.AppendLine();

            var bySource = result.Findings.GroupBy(f => f.Source);
            foreach (var group in bySource)
            {
                sb.AppendLine($"  [{group.Key}]");
                foreach (var finding in group)
                {
                    sb.AppendLine($"    [{finding.Confidence}] {finding.Path}");
                    if (!string.IsNullOrEmpty(finding.Details))
                        sb.AppendLine($"           {finding.Details}");
                    if (finding.Timestamp.HasValue)
                        sb.AppendLine($"           Timestamp: {finding.Timestamp.Value:yyyy-MM-dd HH:mm:ss}");
                }
                sb.AppendLine();
            }

            File.WriteAllText(filename, sb.ToString());
            Info($"Reporte guardado en: {filename}");
        }
    }
}
