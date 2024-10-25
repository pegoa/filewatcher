using System;
using System.IO;
using System.Security.AccessControl;

class FileWatcherExample
{
    private static readonly string WatchDirectory = @"C:\Messdaten"; // Directory to watch
    private static readonly string LogDirectoryPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Messdaten");
    private static readonly string LogFilePath = Path.Combine(LogDirectoryPath, "log.txt");

    public static void Main()
    {
        // Ensure the log directory exists
        EnsureLogDirectoryExists();

        // Setup the FileSystemWatcher
        using (FileSystemWatcher watcher = new FileSystemWatcher(WatchDirectory))
        {
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.DirectoryName;
            watcher.Filter = "*.*"; // Watch all files and folders
            watcher.IncludeSubdirectories = false;

            watcher.Created += OnFileOrFolderCreated; // Attach the event handler
            watcher.EnableRaisingEvents = true; // Start monitoring

            Console.WriteLine($"Watching directory: {WatchDirectory}");
            Console.WriteLine("Press 'q' to quit.");
            while (Console.Read() != 'q') { }
        }

        Log("Service stopped.");
    }

    private static void OnFileOrFolderCreated(object sender, FileSystemEventArgs e)
    {
        Console.WriteLine($"Item created: {e.FullPath}");
        Log($"Item created: {e.FullPath}");

        // Wait for the item to be ready
        if (WaitForFileToBeReady(e.FullPath))
        {
            // Remove existing ACLs for the created item
            RemoveFileSecurity(e.FullPath, @"DOMAIN\Domain Admins", FileSystemRights.FullControl, AccessControlType.Allow); // Adjust as necessary
            RemoveFileSecurity(e.FullPath, "SYSTEM", FileSystemRights.FullControl, AccessControlType.Allow);

            // Add read-only access for everyone else
            AddFileSecurity(e.FullPath, "Everyone", FileSystemRights.Read, AccessControlType.Allow);
            Log($"Updated ACLs for: {e.FullPath}");
        }
    }

    private static bool WaitForFileToBeReady(string path)
    {
        const int maxRetries = 10;
        const int delay = 500; // 500 milliseconds
        int attempts = 0;

        while (attempts < maxRetries)
        {
            try
            {
                // Attempt to open the item exclusively
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    return true; // Item is ready
                }
            }
            catch (IOException)
            {
                attempts++;
                System.Threading.Thread.Sleep(delay); // Wait before retrying
            }
        }
        return false; // Item is not ready after all attempts
    }

    public static void AddFileSecurity(string path, string account,
        FileSystemRights rights, AccessControlType controlType)
    {
        FileInfo fileInfo = new(path);
        FileSecurity fSecurity = fileInfo.GetAccessControl();

        // Add the FileSystemAccessRule to the security settings.
        fSecurity.AddAccessRule(new FileSystemAccessRule(account, rights, controlType));

        // Set the new access settings.
        fileInfo.SetAccessControl(fSecurity);
    }

    public static void RemoveFileSecurity(string path, string account,
        FileSystemRights rights, AccessControlType controlType)
    {
        // Determine if the path is a file or directory
        if (File.Exists(path))
        {
            FileInfo fileInfo = new(path);
            FileSecurity fSecurity = fileInfo.GetAccessControl();

            // Remove the FileSystemAccessRule from the security settings.
            fSecurity.RemoveAccessRule(new FileSystemAccessRule(account, rights, controlType));

            // Set the new access settings.
            fileInfo.SetAccessControl(fSecurity);
        }
        else if (Directory.Exists(path))
        {
            DirectoryInfo dirInfo = new(path);
            DirectorySecurity dirSecurity = dirInfo.GetAccessControl();

            // Remove the FileSystemAccessRule from the directory's security settings.
            dirSecurity.RemoveAccessRule(new FileSystemAccessRule(account, rights, controlType));

            // Set the new access settings.
            dirInfo.SetAccessControl(dirSecurity);
        }
    }

    private static void EnsureLogDirectoryExists()
    {
        if (!Directory.Exists(LogDirectoryPath))
        {
            Directory.CreateDirectory(LogDirectoryPath);
        }
    }

    private static void Log(string message)
    {
        try
        {
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
