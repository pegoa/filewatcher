using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal; // Import for NTAccount
using System.Threading;

class Program
{
    private static readonly string logFilePath = @"C:\service\md.log";
    private const long maxLogFileSize = 50 * 1024 * 1024; // 50 MB
    private static readonly HashSet<string> processedFiles = new HashSet<string>(); // Track processed files

    static void Main(string[] args)
    {
        string directoryToWatch = @"C:\messdaten";
        using (FileSystemWatcher watcher = new FileSystemWatcher(directoryToWatch))
        {
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite; // Monitor both creation and writes
            watcher.Filter = "*.*"; // Watch all files
            watcher.IncludeSubdirectories = true; // Monitor subdirectories

            watcher.Created += OnCreated;
            watcher.EnableRaisingEvents = true;

            Log($"Monitoring {directoryToWatch} and its subdirectories for created files. Press [Enter] to exit.");
            Console.ReadLine();
        }
    }

    private static void OnCreated(object sender, FileSystemEventArgs e)
    {
        // Use a lock to ensure thread safety when accessing the HashSet
        lock (processedFiles)
        {
            // Check if the file has already been processed
            if (processedFiles.Contains(e.FullPath))
            {
                return; // Exit if already processed
            }

            // Mark this file as processed
            processedFiles.Add(e.FullPath);
        }

        try
        {
            // Wait until the file is fully created and not in use
            WaitForFileToBeReady(e.FullPath);

            // Take ownership of the file
            TakeOwnership(e.FullPath);

            // Get the current access control settings for the file
            FileSecurity fileSecurity = File.GetAccessControl(e.FullPath);

            // Protect current rules
            fileSecurity.SetAccessRuleProtection(true, false); // Protect current rules

            // Add read permissions for Authenticated Users
            var authenticatedUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            var readRule = new FileSystemAccessRule(authenticatedUsersSid, FileSystemRights.Read, AccessControlType.Allow);
            fileSecurity.AddAccessRule(readRule);

            // Add full control permissions for Administrators
            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var fullControlRule = new FileSystemAccessRule(administratorsSid, FileSystemRights.FullControl, AccessControlType.Allow);
            fileSecurity.AddAccessRule(fullControlRule);

            // Set the updated access control settings
            File.SetAccessControl(e.FullPath, fileSecurity);
            Log($"Updated permissions for: {e.FullPath}");

            // Apply the same permissions recursively to the parent directory if needed
            string parentDirectory = Path.GetDirectoryName(e.FullPath);
            if (!string.IsNullOrEmpty(parentDirectory))
            {
                ApplyPermissionsRecursively(parentDirectory);
            }
        }
        catch (Exception ex)
        {
            Log($"Error processing file {e.FullPath}: {ex.Message}");
        }
    }

    private static void ApplyPermissionsRecursively(string directoryPath)
    {
        try
        {
            // Get the access control settings for the directory
            DirectorySecurity directorySecurity = Directory.GetAccessControl(directoryPath);

            // Add read permissions for Authenticated Users
            var authenticatedUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            var readRule = new FileSystemAccessRule(authenticatedUsersSid, FileSystemRights.Read, AccessControlType.Allow);
            directorySecurity.AddAccessRule(readRule);

            // Add full control permissions for Administrators
            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var fullControlRule = new FileSystemAccessRule(administratorsSid, FileSystemRights.FullControl, AccessControlType.Allow);
            directorySecurity.AddAccessRule(fullControlRule);

            // Set the updated access control settings for the directory
            Directory.SetAccessControl(directoryPath, directorySecurity);
            // Log($"Updated permissions for directory: {directoryPath}");

            // Recursively apply permissions to subdirectories
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

    private static void TakeOwnership(string filePath)
    {
        // Get the current access control settings for the file
        FileSecurity fileSecurity = File.GetAccessControl(filePath);

        // Set ownership to the Administrators group
        var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        fileSecurity.SetOwner(administratorsSid);

        // Apply the updated ownership
        File.SetAccessControl(filePath, fileSecurity);
        Log($"Ownership taken for: {filePath} by Administrators");
    }

    private static void WaitForFileToBeReady(string filePath)
    {
        const int maxRetries = 10; // Maximum number of attempts
        const int delay = 500; // Delay in milliseconds between attempts
        int attempts = 0;

        while (attempts < maxRetries)
        {
            try
            {
                using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    // If we can open the file, it's ready
                    return;
                }
            }
            catch (IOException)
            {
                // File is still in use, wait and try again
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
            // Rotate the log file if it exceeds the maximum size
            RotateLogFileIfNeeded();

            // Append the message to the log file
            using (StreamWriter writer = new StreamWriter(logFilePath, true))
            {
                writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
            }

            // Also output the log message to the console
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
            // Rename the current log file to include a timestamp
            string backupLogFilePath = Path.Combine(logFileInfo.DirectoryName,
                                                    $"md_{DateTime.Now:yyyyMMdd_HHmmss}.log");
            logFileInfo.MoveTo(backupLogFilePath);
            Log($"Log file rotated: {backupLogFilePath}");
        }
    }
}
