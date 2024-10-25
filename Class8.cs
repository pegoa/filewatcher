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
                    if (fsRule.IdentityReference.Value != "NT-AUTORITÄT\SYSTEM" &&
                        fsRule.IdentityReference.Value != @"VORDEFINIERT\Administratoren")
                    {
                        // Remove the write/modify permission
                        fileSecurity.RemoveAccessRule(fsRule);
                    }
                }

                // Remove "Authenticated Users" completely
                if (fsRule.IdentityReference.Value == "NT-AUTORITÄT\Authentifizierte Benutzer")
                {
                    fileSecurity.RemoveAccessRule(fsRule);
                }
            }
        }

        // Set the updated access control settings
        File.SetAccessControl(e.FullPath, fileSecurity);
        Log($"Updated ACLs for: {e.FullPath}");
    }
    catch (Exception ex)
    {
        Log($"Error processing file {e.FullPath}: {ex.Message}");
    }
}
