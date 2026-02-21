using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace ZentriScanner
{
    public static class DoomsdayDetector
    {
        #region Constants & Patterns

        private static readonly string[] ClassPatterns = {
            "net/java/f", "net/java/g", "net/java/h", "net/java/i",
            "net/java/k", "net/java/l", "net/java/m", "net/java/r",
            "net/java/s", "net/java/t", "net/java/y"
        };

        private static readonly byte[][] BytePatterns;

        private const long MinJarSize = 200 * 1024;
        private const long MaxJarSize = 15 * 1024 * 1024;

        static DoomsdayDetector()
        {
            BytePatterns = new byte[][] {
                new byte[] { 0x61, 0x61, 0x37, 0x0E, 0x16, 0x06, 0x09, 0x94, 0x9E, 0x00, 0x29, 0x03, 0x3E, 0xA7 },
                new byte[] { 0x0C, 0x15, 0x04, 0x85, 0x1D, 0x85, 0x60, 0xA6, 0x16, 0x13, 0x70, 0x0E },
                new byte[] { 0x59, 0x10, 0x07, 0x10, 0x88, 0x54, 0x4C, 0x2A, 0x2B, 0xB8, 0x00, 0x4D }
            };
        }

        #endregion

        #region Result Classes

        public class DoomsdayResult
        {
            public bool IsDetected { get; set; }
            public string Confidence { get; set; } = "NONE";
            public List<DoomsdayFinding> Findings { get; set; } = new();
        }

        public class DoomsdayFinding
        {
            public string Source { get; set; } = "";
            public string Path { get; set; } = "";
            public string Details { get; set; } = "";
            public string Confidence { get; set; } = "LOW";
            public DateTime? Timestamp { get; set; }
        }

        public class JarAnalysisResult
        {
            public bool IsDetected { get; set; }
            public string Confidence { get; set; } = "NONE";
            public int BytePatternMatches { get; set; }
            public int ClassNameMatches { get; set; }
            public int SingleLetterClasses { get; set; }
            public bool IsRenamedJar { get; set; }
            public List<string> MatchedPatterns { get; set; } = new();
            public string Error { get; set; } = "";
        }

        #endregion

        #region Main Entry Point

        public static DoomsdayResult RunFullScan(bool verbose = false)
        {
            var result = new DoomsdayResult();

            Console.WriteLine();
            WriteHeader("DOOMSDAY CLIENT FORENSICS SCAN");
            Console.WriteLine();

            Info("Analizando Prefetch...");
            var prefetchFindings = ScanPrefetch(verbose);
            result.Findings.AddRange(prefetchFindings);

            Info("Escaneando JARs en disco...");
            var jarFindings = ScanJarsOnDisk(verbose);
            result.Findings.AddRange(jarFindings);

            Info("Leyendo USN Journal...");
            var usnFindings = ScanUSNJournal(verbose);
            result.Findings.AddRange(usnFindings);

            Info("Verificando dcomlaunch...");
            var dcomFindings = CheckDcomLaunch(verbose);
            result.Findings.AddRange(dcomFindings);

            result.IsDetected = result.Findings.Count > 0;
            result.Confidence = CalculateOverallConfidence(result.Findings);

            return result;
        }

        #endregion

        #region Prefetch Analysis

        private static List<DoomsdayFinding> ScanPrefetch(bool verbose)
        {
            var findings = new List<DoomsdayFinding>();
            string prefetchPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

            if (!Directory.Exists(prefetchPath))
            {
                Warn("Directorio Prefetch no encontrado");
                return findings;
            }

            try
            {
                var javaFiles = Directory.GetFiles(prefetchPath, "JAVA*.pf", SearchOption.TopDirectoryOnly);

                if (javaFiles.Length == 0)
                {
                    Info("No se encontraron archivos Prefetch de Java");
                    return findings;
                }

                Info($"Encontrados {javaFiles.Length} archivos Prefetch de Java");

                foreach (var pfFile in javaFiles)
                {
                    try
                    {
                        var paths = ExtractPrefetchPaths(pfFile, verbose);
                        
                        foreach (var path in paths)
                        {
                            if (IsSuspiciousJarPath(path))
                            {
                                var finding = new DoomsdayFinding
                                {
                                    Source = "Prefetch",
                                    Path = path,
                                    Details = $"JAR sospechoso ejecutado (desde {Path.GetFileName(pfFile)})",
                                    Confidence = "MEDIUM"
                                };

                                if (!File.Exists(path))
                                {
                                    finding.Details += " [ARCHIVO BORRADO]";
                                    finding.Confidence = "HIGH";
                                }

                                findings.Add(finding);

                                if (verbose)
                                    Detail($"  Prefetch: {path}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (verbose)
                            Warn($"Error procesando {Path.GetFileName(pfFile)}: {ex.Message}");
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Warn("Sin permisos para leer Prefetch. Ejecuta como Administrador.");
            }

            return findings;
        }

        private static List<string> ExtractPrefetchPaths(string pfFile, bool verbose)
        {
            var paths = new List<string>();
            byte[] data = File.ReadAllBytes(pfFile);

            if (data.Length >= 8 && data[0] == 0x4D && data[1] == 0x41 && data[2] == 0x4D)
            {
                var decompressed = DecompressPrefetch(data);
                if (decompressed == null)
                {
                    if (verbose) Warn($"No se pudo descomprimir: {Path.GetFileName(pfFile)}");
                    return paths;
                }
                data = decompressed;
            }

            if (data.Length < 108) return paths;
            string sig = Encoding.ASCII.GetString(data, 4, 4);
            if (sig != "SCCA") return paths;

            uint stringsOffset = BitConverter.ToUInt32(data, 100);
            uint stringsSize = BitConverter.ToUInt32(data, 104);

            if (stringsOffset == 0 || stringsSize == 0) return paths;
            if (stringsOffset >= data.Length || stringsOffset + stringsSize > data.Length) return paths;

            int pos = (int)stringsOffset;
            int endPos = (int)(stringsOffset + stringsSize);

            while (pos < endPos && pos < data.Length - 2)
            {
                int nullPos = pos;
                while (nullPos < data.Length - 1)
                {
                    if (data[nullPos] == 0 && data[nullPos + 1] == 0)
                        break;
                    nullPos += 2;
                }

                if (nullPos > pos)
                {
                    int strLen = nullPos - pos;
                    if (strLen > 0 && strLen < 2048)
                    {
                        try
                        {
                            string filename = Encoding.Unicode.GetString(data, pos, strLen);
                            if (!string.IsNullOrWhiteSpace(filename))
                            {
                                if (filename.Contains("\\VOLUME{"))
                                {
                                    var match = Regex.Match(filename, @"\\VOLUME\{[^\}]+\}\\(.*)$", RegexOptions.IgnoreCase);
                                    if (match.Success)
                                        filename = "C:\\" + match.Groups[1].Value;
                                }
                                paths.Add(filename);
                            }
                        }
                        catch { }
                    }
                }

                pos = nullPos + 2;
                if (paths.Count > 1000) break;
            }

            return paths;
        }

        private static byte[]? DecompressPrefetch(byte[] compressed)
        {
            if (compressed.Length < 8) return null;

            int uncompSize = BitConverter.ToInt32(compressed, 4);
            if (uncompSize <= 0 || uncompSize > 50 * 1024 * 1024) return null;

            try
            {
                uint wsComp, wsFrag;
                if (NtdllDecompressor.RtlGetCompressionWorkSpaceSize(4, out wsComp, out wsFrag) != 0)
                    return null;

                IntPtr workspace = Marshal.AllocHGlobal((int)wsFrag);
                byte[] result = new byte[uncompSize];

                try
                {
                    byte[] compData = new byte[compressed.Length - 8];
                    Array.Copy(compressed, 8, compData, 0, compData.Length);

                    int finalSize;
                    uint status = NtdllDecompressor.RtlDecompressBufferEx(
                        4, result, uncompSize, compData, compData.Length, out finalSize, workspace);

                    return status == 0 ? result : null;
                }
                finally
                {
                    Marshal.FreeHGlobal(workspace);
                }
            }
            catch
            {
                return null;
            }
        }

        private static bool IsSuspiciousJarPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            
            string lower = path.ToLowerInvariant();
            
            bool isJarLike = lower.EndsWith(".jar") || 
                            Regex.IsMatch(Path.GetFileName(lower), @"^[a-z0-9]{8,}$");

            if (!isJarLike) return false;

            string[] suspiciousPaths = {
                "\\temp\\", "\\tmp\\", "\\downloads\\", "\\desktop\\",
                "\\appdata\\local\\", "\\appdata\\roaming\\",
                "\\users\\", "\\programdata\\"
            };

            string[] safePaths = {
                "\\.minecraft\\mods\\", "\\.minecraft\\versions\\",
                "\\curseforge\\", "\\polymc\\", "\\prism",
                "\\feather\\", "\\lunar\\"
            };

            foreach (var safe in safePaths)
                if (lower.Contains(safe)) return false;

            string filename = Path.GetFileNameWithoutExtension(path);
            bool hasRandomName = Regex.IsMatch(filename, @"^[a-z0-9]{6,20}$", RegexOptions.IgnoreCase) &&
                                !filename.Contains("-") && !filename.Contains("_");

            foreach (var susp in suspiciousPaths)
                if (lower.Contains(susp) && hasRandomName) return true;

            return hasRandomName;
        }

        #endregion

        #region JAR Scanner

        private static List<DoomsdayFinding> ScanJarsOnDisk(bool verbose)
        {
            var findings = new List<DoomsdayFinding>();

            string[] searchPaths = {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Downloads")
            };

            string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!searchPaths.Contains(downloads))
                searchPaths = searchPaths.Append(downloads).ToArray();

            var scannedJars = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int totalScanned = 0;

            foreach (var basePath in searchPaths)
            {
                if (!Directory.Exists(basePath)) continue;

                try
                {
                    var files = Directory.EnumerateFiles(basePath, "*", SearchOption.AllDirectories)
                        .Where(f => {
                            string ext = Path.GetExtension(f).ToLower();
                            long size = 0;
                            try { size = new FileInfo(f).Length; } catch { return false; }
                            
                            if (size < MinJarSize || size > MaxJarSize) return false;
                            
                            return ext == ".jar" || string.IsNullOrEmpty(ext) || 
                                   Regex.IsMatch(Path.GetFileName(f), @"^[A-Za-z0-9]{6,}$");
                        })
                        .Take(500);

                    foreach (var file in files)
                    {
                        if (scannedJars.Contains(file)) continue;
                        scannedJars.Add(file);

                        if (file.ToLower().Contains("\\.minecraft\\mods\\") ||
                            file.ToLower().Contains("\\.minecraft\\versions\\") ||
                            file.ToLower().Contains("\\curseforge\\"))
                            continue;

                        totalScanned++;
                        if (verbose && totalScanned % 50 == 0)
                            Detail($"  Escaneados {totalScanned} archivos...");

                        var analysis = AnalyzeJar(file, verbose);
                        
                        if (analysis.IsDetected)
                        {
                            var finding = new DoomsdayFinding
                            {
                                Source = "JAR Scanner",
                                Path = file,
                                Confidence = analysis.Confidence,
                                Details = BuildJarDetails(analysis)
                            };

                            findings.Add(finding);
                            
                            if (verbose)
                                Detail($"  [!] Detectado: {file} ({analysis.Confidence})");
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception ex)
                {
                    if (verbose) Warn($"Error escaneando {basePath}: {ex.Message}");
                }
            }

            Info($"Escaneados {totalScanned} archivos JAR/sospechosos");
            return findings;
        }

        public static JarAnalysisResult AnalyzeJar(string path, bool verbose = false)
        {
            var result = new JarAnalysisResult();

            if (!File.Exists(path))
            {
                result.Error = "Archivo no encontrado";
                return result;
            }

            try
            {
                byte[] header = new byte[4];
                using (var fs = File.OpenRead(path))
                {
                    if (fs.Read(header, 0, 4) < 4)
                    {
                        result.Error = "Archivo muy pequeño";
                        return result;
                    }
                }

                bool isPK = header[0] == 0x50 && header[1] == 0x4B;
                string ext = Path.GetExtension(path).ToLower();

                if (isPK && ext != ".jar" && ext != ".zip")
                {
                    result.IsRenamedJar = true;
                    result.MatchedPatterns.Add("JAR renombrado (magic bytes PK)");
                }

                if (!isPK)
                {
                    result.Error = "No es un archivo JAR/ZIP";
                    return result;
                }

                using var zip = ZipFile.OpenRead(path);
                var classFiles = zip.Entries.Where(e => e.FullName.EndsWith(".class")).ToList();

                if (classFiles.Count == 0)
                {
                    result.Error = "No contiene archivos .class";
                    return result;
                }

                if (classFiles.Count > 30)
                {
                    result.Error = $"Demasiadas clases ({classFiles.Count}), probablemente librería legítima";
                    return result;
                }

                foreach (var entry in classFiles)
                {
                    string className = Path.GetFileNameWithoutExtension(entry.FullName);
                    if (Regex.IsMatch(className, @"^[a-zA-Z]$"))
                    {
                        result.SingleLetterClasses++;
                        
                        string fullPath = entry.FullName.Replace(".class", "");
                        foreach (var pattern in ClassPatterns)
                        {
                            if (fullPath.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                result.ClassNameMatches++;
                                result.MatchedPatterns.Add(pattern);
                            }
                        }
                    }
                }

                using var ms = new MemoryStream();
                foreach (var entry in classFiles)
                {
                    using var entryStream = entry.Open();
                    entryStream.CopyTo(ms);
                }
                byte[] allBytes = ms.ToArray();

                foreach (var pattern in BytePatterns)
                {
                    if (ContainsPattern(allBytes, pattern))
                    {
                        result.BytePatternMatches++;
                        result.MatchedPatterns.Add($"Byte pattern #{result.BytePatternMatches}");
                    }
                }

                var fabricEntry = zip.GetEntry("fabric.mod.json");
                if (fabricEntry != null)
                {
                    using var reader = new StreamReader(fabricEntry.Open());
                    string content = reader.ReadToEnd();
                    if (content.Contains("\"id\":\"dd\"") || content.Contains("\"id\": \"dd\""))
                    {
                        result.MatchedPatterns.Add("fabric.mod.json: id=\"dd\"");
                        result.ClassNameMatches++;
                    }
                    if (content.Contains("net.java.h"))
                    {
                        result.MatchedPatterns.Add("fabric.mod.json: entrypoint net.java.h");
                        result.ClassNameMatches++;
                    }
                }

                var modsTomlEntry = zip.GetEntry("META-INF/mods.toml");
                if (modsTomlEntry != null)
                {
                    using var reader = new StreamReader(modsTomlEntry.Open());
                    string content = reader.ReadToEnd();
                    if (content.Contains("modId=\"dd\"") || content.Contains("modId = \"dd\""))
                    {
                        result.MatchedPatterns.Add("mods.toml: modId=\"dd\"");
                        result.ClassNameMatches++;
                    }
                }

                if (result.BytePatternMatches >= 2)
                {
                    result.IsDetected = true;
                    result.Confidence = "HIGH";
                }
                else if (result.BytePatternMatches >= 1 && (result.ClassNameMatches >= 5 || result.SingleLetterClasses >= 5))
                {
                    result.IsDetected = true;
                    result.Confidence = "MEDIUM";
                }
                else if (result.BytePatternMatches >= 1)
                {
                    result.IsDetected = true;
                    result.Confidence = "LOW";
                }
                else if (result.SingleLetterClasses >= 8 && result.ClassNameMatches >= 3)
                {
                    result.IsDetected = true;
                    result.Confidence = "MEDIUM";
                }
                else if (result.SingleLetterClasses >= 5 || result.ClassNameMatches >= 5)
                {
                    result.IsDetected = true;
                    result.Confidence = "LOW";
                }

                if (result.IsRenamedJar && !result.IsDetected)
                {
                    result.IsDetected = true;
                    result.Confidence = "LOW";
                }
            }
            catch (InvalidDataException)
            {
                result.Error = "Archivo ZIP/JAR corrupto";
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private static string BuildJarDetails(JarAnalysisResult analysis)
        {
            var parts = new List<string>();
            
            if (analysis.BytePatternMatches > 0)
                parts.Add($"BytePatterns: {analysis.BytePatternMatches}");
            if (analysis.ClassNameMatches > 0)
                parts.Add($"ClassMatches: {analysis.ClassNameMatches}");
            if (analysis.SingleLetterClasses > 0)
                parts.Add($"SingleLetter: {analysis.SingleLetterClasses}");
            if (analysis.IsRenamedJar)
                parts.Add("JAR renombrado");
            if (analysis.MatchedPatterns.Count > 0)
                parts.Add($"Patterns: {string.Join(", ", analysis.MatchedPatterns.Take(3))}");

            return string.Join(" | ", parts);
        }

        private static bool ContainsPattern(byte[] data, byte[] pattern)
        {
            if (pattern.Length > data.Length) return false;

            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }

        #endregion

        #region USN Journal

        private static List<DoomsdayFinding> ScanUSNJournal(bool verbose)
        {
            var findings = new List<DoomsdayFinding>();

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "fsutil",
                    Arguments = "usn readjournal C:",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null)
                {
                    Warn("No se pudo iniciar fsutil");
                    return findings;
                }

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(30000);

                if (process.ExitCode != 0)
                {
                    Warn("Error al leer USN Journal (se requieren permisos de Administrador)");
                    return findings;
                }

                var lines = output.Split('\n');
                string currentFile = "";
                DateTime? currentTime = null;
                string currentReason = "";
                var cutoffTime = DateTime.Now.AddMinutes(-60);

                foreach (var line in lines)
                {
                    if (line.Contains("File name") && line.Contains(":"))
                    {
                        var match = Regex.Match(line, @"File name\s*:\s*(.+)$");
                        if (match.Success)
                            currentFile = match.Groups[1].Value.Trim();
                    }
                    else if (line.Contains("Time stamp") && line.Contains(":"))
                    {
                        var match = Regex.Match(line, @"Time stamp\s*:\s*(.+)$");
                        if (match.Success && DateTime.TryParse(match.Groups[1].Value.Trim(), out DateTime dt))
                            currentTime = dt;
                    }
                    else if (line.Contains("Reason") && line.Contains(":"))
                    {
                        var match = Regex.Match(line, @"Reason\s*:\s*(.+)$");
                        if (match.Success)
                            currentReason = match.Groups[1].Value.Trim();

                        if (currentFile.ToLower().EndsWith(".jar") || 
                            Regex.IsMatch(currentFile, @"^[a-z0-9]{8,}$", RegexOptions.IgnoreCase))
                        {
                            if (currentTime.HasValue && currentTime.Value > cutoffTime)
                            {
                                bool isDelete = currentReason.Contains("FILE_DELETE") || 
                                               currentReason.Contains("CLOSE");

                                if (IsSuspiciousFileName(currentFile))
                                {
                                    findings.Add(new DoomsdayFinding
                                    {
                                        Source = "USN Journal",
                                        Path = currentFile,
                                        Timestamp = currentTime,
                                        Confidence = isDelete ? "MEDIUM" : "LOW",
                                        Details = $"Actividad reciente: {currentReason}"
                                    });

                                    if (verbose)
                                        Detail($"  USN: {currentFile} ({currentReason})");
                                }
                            }
                        }

                        currentFile = "";
                        currentTime = null;
                        currentReason = "";
                    }
                }

                Info($"USN Journal: {findings.Count} actividades sospechosas");
            }
            catch (Exception ex)
            {
                if (verbose) Warn($"Error leyendo USN Journal: {ex.Message}");
            }

            return findings;
        }

        private static bool IsSuspiciousFileName(string filename)
        {
            if (string.IsNullOrEmpty(filename)) return false;
            
            string name = Path.GetFileNameWithoutExtension(filename);
            
            if (Regex.IsMatch(name, @"^[a-z0-9]{6,20}$", RegexOptions.IgnoreCase) &&
                !name.Contains("-") && !name.Contains("_"))
                return true;

            string[] knownPatterns = { "dd", "doomsday", "doom" };
            foreach (var pattern in knownPatterns)
                if (name.ToLower().Contains(pattern)) return true;

            return false;
        }

        #endregion

        #region dcomlaunch Detection

        private static List<DoomsdayFinding> CheckDcomLaunch(bool verbose)
        {
            var findings = new List<DoomsdayFinding>();

            try
            {
                var processes = Process.GetProcessesByName("java")
                    .Concat(Process.GetProcessesByName("javaw"));

                foreach (var proc in processes)
                {
                    try
                    {
                        var parentId = GetParentProcessId(proc.Id);
                        if (parentId > 0)
                        {
                            var parent = Process.GetProcessById(parentId);
                            
                            if (parent.ProcessName.Equals("svchost", StringComparison.OrdinalIgnoreCase))
                            {
                                findings.Add(new DoomsdayFinding
                                {
                                    Source = "dcomlaunch",
                                    Path = $"PID {proc.Id} ({proc.ProcessName})",
                                    Confidence = "HIGH",
                                    Details = $"Proceso Java iniciado por svchost (PID {parentId}) - posible inyección"
                                });

                                if (verbose)
                                    Detail($"  [!] Java PID {proc.Id} iniciado por svchost");
                            }
                        }
                    }
                    catch { }
                }

                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "wevtutil",
                        Arguments = "qe System /q:\"*[System[Provider[@Name='DCOM'] and (EventID=10016)]]\" /c:10 /f:text",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(psi);
                    if (process != null)
                    {
                        string output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit(10000);

                        if (output.ToLower().Contains("java") || output.ToLower().Contains("jre") ||
                            output.ToLower().Contains("jdk"))
                        {
                            findings.Add(new DoomsdayFinding
                            {
                                Source = "dcomlaunch",
                                Path = "Event Viewer",
                                Confidence = "MEDIUM",
                                Details = "Errores DCOM relacionados con Java encontrados"
                            });
                        }
                    }
                }
                catch { }

                Info($"dcomlaunch: {findings.Count} indicadores sospechosos");
            }
            catch (Exception ex)
            {
                if (verbose) Warn($"Error verificando dcomlaunch: {ex.Message}");
            }

            return findings;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength, out int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private static int GetParentProcessId(int pid)
        {
            try
            {
                var handle = WinApi.OpenProcess(WinApi.PROCESS_QUERY_INFORMATION, false, pid);
                if (handle == IntPtr.Zero) return 0;

                try
                {
                    PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                    int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                    
                    if (status == 0)
                        return pbi.InheritedFromUniqueProcessId.ToInt32();
                }
                finally
                {
                    WinApi.CloseHandle(handle);
                }
            }
            catch { }
            return 0;
        }

        #endregion

        #region Helpers

        private static string CalculateOverallConfidence(List<DoomsdayFinding> findings)
        {
            if (findings.Count == 0) return "NONE";

            int highCount = findings.Count(f => f.Confidence == "HIGH");
            int mediumCount = findings.Count(f => f.Confidence == "MEDIUM");

            if (highCount >= 1) return "HIGH";
            if (mediumCount >= 2) return "HIGH";
            if (mediumCount >= 1) return "MEDIUM";
            return "LOW";
        }

        private static void WriteHeader(string text)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(new string('═', 60));
            Console.WriteLine($"  {text}");
            Console.WriteLine(new string('═', 60));
            Console.ResetColor();
        }

        private static void Info(string msg)
        {
            Console.Write("  ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("[*] ");
            Console.ResetColor();
            Console.WriteLine(msg);
        }

        private static void Warn(string msg)
        {
            Console.Write("  ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("[!] ");
            Console.ResetColor();
            Console.WriteLine(msg);
        }

        private static void Detail(string msg)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(msg);
            Console.ResetColor();
        }

        #endregion

        #region Results Printing

        public static void PrintResults(DoomsdayResult result)
        {
            Console.WriteLine();
            WriteHeader("RESULTADOS DOOMSDAY SCAN");
            Console.WriteLine();

            if (!result.IsDetected)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  ✓ No se detectó Doomsday Client");
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ⚠ DOOMSDAY CLIENT DETECTADO - Confianza: {result.Confidence}");
            Console.ResetColor();
            Console.WriteLine();

            Console.WriteLine($"  Total de indicadores: {result.Findings.Count}");
            Console.WriteLine();

            var bySource = result.Findings.GroupBy(f => f.Source);
            foreach (var group in bySource)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [{group.Key}]");
                Console.ResetColor();

                foreach (var finding in group)
                {
                    Console.Write("    ");
                    
                    switch (finding.Confidence)
                    {
                        case "HIGH":
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Write("[HIGH] ");
                            break;
                        case "MEDIUM":
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.Write("[MED]  ");
                            break;
                        default:
                            Console.ForegroundColor = ConsoleColor.Gray;
                            Console.Write("[LOW]  ");
                            break;
                    }
                    Console.ResetColor();

                    Console.WriteLine(finding.Path);

                    if (!string.IsNullOrEmpty(finding.Details))
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"           {finding.Details}");
                        Console.ResetColor();
                    }

                    if (finding.Timestamp.HasValue)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"           Timestamp: {finding.Timestamp.Value:yyyy-MM-dd HH:mm:ss}");
                        Console.ResetColor();
                    }
                }
                Console.WriteLine();
            }
        }

        #endregion
    }

    #region Native Decompressor

    internal static class NtdllDecompressor
    {
        [DllImport("ntdll.dll")]
        public static extern uint RtlDecompressBufferEx(
            ushort CompressionFormat,
            byte[] UncompressedBuffer,
            int UncompressedBufferSize,
            byte[] CompressedBuffer,
            int CompressedBufferSize,
            out int FinalUncompressedSize,
            IntPtr WorkSpace);

        [DllImport("ntdll.dll")]
        public static extern uint RtlGetCompressionWorkSpaceSize(
            ushort CompressionFormat,
            out uint CompressBufferWorkSpaceSize,
            out uint CompressFragmentWorkSpaceSize);
    }

    #endregion
}
