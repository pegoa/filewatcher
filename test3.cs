using System;
using System.IO;
using System.Security.AccessControl;

class Program
{
    private static readonly string logFilePath = @"C:\service\md.log";
    private const long maxLogFileSize = 50 * 1024 * 1024; // 50 MB

    static void Main(string[] args)
    {
        string directoryToWatch = @"C:\messdaten";
        using (FileSystemWatcher watcher = new FileSystemWatcher(directoryToWatch))
        {
            watcher.NotifyFilter = NotifyFilters.FileName;
            watcher.Filter = "*.*"; // Watch all files

            watcher.Created += OnCreated;
            watcher.EnableRaisingEvents = true;

            Log($"Monitoring {directoryToWatch} for created files. Press [Enter] to exit.");
            Console.ReadLine();
        }
    }

    private static void OnCreated(object sender, FileSystemEventArgs e)
    {
        try
        {
            // Wait a moment for the file to be fully created
            System.Threading.Thread.Sleep(500);

            // Get the current access control settings for the file
            FileSecurity fileSecurity = File.GetAccessControl(e.FullPath);

            // Protect current rules
            fileSecurity.SetAccessRuleProtection(true, false); // Protect current rules

            // Iterate through the access rules
            AuthorizationRuleCollection rules = fileSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

            foreach (AuthorizationRule rule in rules)
            {
                if (rule is FileSystemAccessRule fsRule)
                {
                    // Check if the rule grants Write or Modify permissions
                    if (fsRule.FileSystemRights.HasFlag(FileSystemRights.Write) ||
                        fsRule.FileSystemRights.HasFlag(FileSystemRights.Modify))
                    {
                        // Skip SYSTEM and DOMAIN\Admins
                        if (fsRule.IdentityReference.Value != "NT-AUTORITÄT\\SYSTEM" &&
                            fsRule.IdentityReference.Value != @"VORDEFINIERT\Administratoren")
                        {
                            // Remove the write/modify permission
                            fileSecurity.RemoveAccessRule(fsRule);
                        }
                    }
                }
            }

            // Set the updated access control settings
            File.SetAccessControl(e.FullPath, fileSecurity);
            Log($"Removed write and modify permissions from: {e.FullPath}");
        }
        catch (Exception ex)
        {
            Log($"Error processing file {e.FullPath}: {ex.Message}");
        }
    }

    private static void Log(string message)
    {
        try
        {
            // Rotate the log file if it exceeds the maximum size
            RotateLogFileIfNeeded();

            // Append the message to the log file
            using (StreamWriter writer = new StreamWriter(logFilePath, true))
            {
                writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Logging error: {ex.Message}");
        }
    }

    private static void RotateLogFileIfNeeded()
    {
        FileInfo logFileInfo = new FileInfo(logFilePath);
        if (logFileInfo.Exists && logFileInfo.Length >= maxLogFileSize)
        {
            // Rename the current log file to include a timestamp
            string backupLogFilePath = Path.Combine(logFileInfo.DirectoryName,
                                                    $"md_{DateTime.Now:yyyyMMdd_HHmmss}.log");
            logFileInfo.MoveTo(backupLogFilePath);
        }
    }
}
