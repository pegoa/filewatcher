using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

class Program
{
    private static readonly string logFilePath = @"C:\Programme\Kuhn-Computer\SAS-Filewatcher-Messdaten.log";
    private const long maxLogFileSize = 50 * 1024 * 1024; // 50 MB
    // private static readonly HashSet<string> processedFiles = new HashSet<string>(); // Track processed files

    static void Main(string[] args)
    {
        string directoryToWatch = @"C:\Daten\IR\Omnic\Spectra\TEST";
        using (FileSystemWatcher watcher = new FileSystemWatcher(directoryToWatch))
        {
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite;
            watcher.Filter = "*.*"; // Watch all files
            watcher.IncludeSubdirectories = true; // Monitor subdirectories

            watcher.Created += OnCreated;
            watcher.EnableRaisingEvents = true;

            Log($"Monitoring {directoryToWatch} and its subdirectories for created files and directories. Press [Enter] to exit.");
            Console.ReadLine();
        }
    }

    private static void OnCreated(object sender, FileSystemEventArgs e)
    {
        //    lock (processedFiles)
        //    {
        //        if (processedFiles.Contains(e.FullPath)) return;
        //        processedFiles.Add(e.FullPath);
        //    }

        try
        {
            WaitForFileToBeReady(e.FullPath);

            if (Directory.Exists(e.FullPath))
            {
                // Take ownership and modify ACLs for new directories
                TakeOwnershipAndModifyAcls(e.FullPath, true);
                Log($"Ownership and ACLs set for new directory: {e.FullPath}");
            }
            else if (File.Exists(e.FullPath))
            {
                // Take ownership and modify ACLs for new files
                TakeOwnershipAndModifyAcls(e.FullPath, false);
                Log($"Ownership and ACLs set for new file: {e.FullPath}");

                // Apply permissions to the parent directory if necessary
                string parentDirectory = Path.GetDirectoryName(e.FullPath);
                if (!string.IsNullOrEmpty(parentDirectory))
                {
                    ApplyPermissionsRecursively(parentDirectory);
                }
            }
        }
        catch (Exception ex)
        {
            Log($"Error processing item {e.FullPath}: {ex.Message}");
        }
    }

    private static void ApplyPermissionsRecursively(string directoryPath)
    {
        try
        {
            DirectorySecurity directorySecurity = Directory.GetAccessControl(directoryPath);

            var authenticatedUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            var readRule = new FileSystemAccessRule(authenticatedUsersSid, FileSystemRights.Read, AccessControlType.Allow);
            directorySecurity.AddAccessRule(readRule);

            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var fullControlRule = new FileSystemAccessRule(administratorsSid, FileSystemRights.FullControl, AccessControlType.Allow);
            directorySecurity.AddAccessRule(fullControlRule);

            Directory.SetAccessControl(directoryPath, directorySecurity);
            Log($"Updated permissions for directory: {directoryPath}");

            foreach (string subDirectory in Directory.GetDirectories(directoryPath))
            {
                ApplyPermissionsRecursively(subDirectory);
            }
        }
        catch (Exception ex)
        {
            Log($"Error applying permissions to directory {directoryPath}: {ex.Message}");
        }
    }

    private static void TakeOwnershipAndModifyAcls(string path, bool isDirectory)
    {
        try
        {
            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var authenticatedUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);

            if (isDirectory)
            {
                DirectorySecurity directorySecurity = Directory.GetAccessControl(path);
                directorySecurity.SetOwner(administratorsSid);

                directorySecurity.SetAccessRuleProtection(true, false);

                var readRule = new FileSystemAccessRule(authenticatedUsersSid, FileSystemRights.Read, AccessControlType.Allow);
                directorySecurity.AddAccessRule(readRule);

                var fullControlRule = new FileSystemAccessRule(administratorsSid, FileSystemRights.FullControl, AccessControlType.Allow);
                directorySecurity.AddAccessRule(fullControlRule);

                Directory.SetAccessControl(path, directorySecurity);
            }
            else
            {
                FileSecurity fileSecurity = File.GetAccessControl(path);
                fileSecurity.SetOwner(administratorsSid);

                fileSecurity.SetAccessRuleProtection(true, false);

                var readRule = new FileSystemAccessRule(authenticatedUsersSid, FileSystemRights.Read, AccessControlType.Allow);
                fileSecurity.AddAccessRule(readRule);

                var fullControlRule = new FileSystemAccessRule(administratorsSid, FileSystemRights.FullControl, AccessControlType.Allow);
                fileSecurity.AddAccessRule(fullControlRule);

                File.SetAccessControl(path, fileSecurity);
            }

            Log($"Ownership and ACLs modified for: {path}");
        }
        catch (Exception ex)
        {
            Log($"Error setting ownership and ACLs for {path}: {ex.Message}");
        }
    }

    private static void WaitForFileToBeReady(string filePath)
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
                    return;
                }
            }
            catch (IOException)
            {
                attempts++;
                Thread.Sleep(delay);
            }
        }

        Log($"File {filePath} did not become ready in time.");
    }

    private static void Log(string message)
    {
        try
        {
            RotateLogFileIfNeeded();

            using (StreamWriter writer = new StreamWriter(logFilePath, true))
            {
                writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
            }

            Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
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
            string backupLogFilePath = Path.Combine(logFileInfo.DirectoryName,
                                                    $"md_{DateTime.Now:yyyyMMdd_HHmmss}.log");
            logFileInfo.MoveTo(backupLogFilePath);
            Log($"Log file rotated: {backupLogFilePath}");
        }
    }
}
