using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;

namespace FileWatcherConsoleApp
{
    class Program
    {
        // Define a static log path
        private static readonly string LogDirectoryPath = @"C:\Service"; // Set your desired log path here
        private static readonly string LogFilePath = Path.Combine(LogDirectoryPath, "log.txt");
        private static readonly long MaxLogSizeBytes = 50 * 1024 * 1024; // 50 MB

        private static readonly ConcurrentQueue<string> FileQueue = new ConcurrentQueue<string>();

        static void Main(string[] args)
        {
            Console.WriteLine("Starting file watcher for C:\\Messdaten...");
            Log("Service started.");

            Task.Run(() => ProcessFileQueue());

            using (FileSystemWatcher watcher = new FileSystemWatcher(@"C:\Messdaten"))
            {
                watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
                watcher.Filter = "*.*";
                watcher.IncludeSubdirectories = false;
                watcher.Created += OnFileCreated;
                watcher.EnableRaisingEvents = true;

                Console.WriteLine("Press 'q' to quit.");
                while (Console.Read() != 'q') { }
                Log("Service stopped.");
            }
        }

        private static void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            FileQueue.Enqueue(e.FullPath);
            Log($"Queued new file: {e.FullPath}");
        }

        private static void ProcessFileQueue()
        {
            while (true)
            {
                if (FileQueue.TryDequeue(out string filePath))
                {
                    if (WaitForFileToBeReady(filePath))
                    {
                        Log($"Processing file: {filePath}");
                        SetReadOnlyAccess(filePath);
                    }
                }
                Thread.Sleep(100);
            }
        }

        private static bool WaitForFileToBeReady(string filePath)
        {
            const int maxRetries = 10;
            const int delay = 500;
            int attempts = 0;

            while (attempts < maxRetries)
            {
                try
                {
                    using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        return true;
                    }
                }
                catch (IOException)
                {
                    attempts++;
                    Thread.Sleep(delay);
                }
            }
            return false;
        }

        private static void SetReadOnlyAccess(string filePath)
        {
            try
            {
                FileSecurity fileSecurity = File.GetAccessControl(filePath);
                AuthorizationRuleCollection rules = fileSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

                foreach (AuthorizationRule rule in rules)
                {
                    if (rule is FileSystemAccessRule accessRule)
                    {
                        string identity = accessRule.IdentityReference.Value;

                        if (identity.Equals("NT-AUTORITÄT\\SYSTEM", StringComparison.OrdinalIgnoreCase))
                        {
                            fileSecurity.AddAccessRule(new FileSystemAccessRule(
                                identity,
                                FileSystemRights.FullControl,
                                AccessControlType.Allow));
                        }
                        else
                        {
                            fileSecurity.RemoveAccessRule(accessRule);
                            fileSecurity.AddAccessRule(new FileSystemAccessRule(
                                identity,
                                FileSystemRights.Read,
                                AccessControlType.Allow));
                        }
                    }
                }

                File.SetAccessControl(filePath, fileSecurity);
                Log($"Access control updated: Only SYSTEM and Domain Admins have full control; others have read-only access on {filePath}");
            }
            catch (Exception ex)
            {
                Log($"Error setting ACLs for {filePath}: {ex.Message}");
            }
        }

        private static void Log(string message)
        {
            try
            {
                if (!Directory.Exists(LogDirectoryPath))
                {
                    Directory.CreateDirectory(LogDirectoryPath);
                }

                // Rotate log file if it exceeds the maximum size
                if (File.Exists(LogFilePath) && new FileInfo(LogFilePath).Length > MaxLogSizeBytes)
                {
                    string archivePath = Path.Combine(LogDirectoryPath, $"log_{DateTime.Now:yyyyMMddHHmmss}.txt");
                    File.Move(LogFilePath, archivePath);
                }

                using (StreamWriter writer = new StreamWriter(LogFilePath, append: true))
                {
                    writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to log message: {ex.Message}");
            }
        }
    }
}
