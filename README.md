[README.md](https://github.com/user-attachments/files/25344756/README.md)
# AzureHound Permission Validator

PowerShell script to validate all required permissions for an [AzureHound Enterprise](https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration) service principal in one shot.

## What it checks

- **Microsoft Graph API permissions** — `Directory.Read.All`, `RoleManagement.Read.All`, `AuditLog.Read.All` (optional)
- **Entra ID role** — `Directory Readers` (via unified RBAC API, catches PIM-assigned roles)
- **Azure RBAC role** — `Reader` on subscriptions

## Prerequisites

```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Install-Module Az.Resources -Scope CurrentUser -Force
Install-Module Az.Accounts -Scope CurrentUser -Force
```

## Execution Policy

If you get the error `File cannot be loaded. The file is not digitally signed`, you need to adjust the PowerShell execution policy. Run one of the following:

```powershell
# Option 1 — Allow for current session only (resets when you close PowerShell)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Option 2 — Allow for current user (persists)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Option 3 — Run the script directly without changing policy
powershell -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1
```

## Usage

```powershell
# Default — looks for app named "AzureHound"
.\AZ_Permissions-Test.ps1

# Custom app name and tenant
.\AZ_Permissions-Test.ps1 -AppName "BloodHound Enterprise Collector" -TenantId "your-tenant-id"
```

## Example output

```
====================================
 AzureHound Permission Validator
====================================
App Name:    AzureHound
Object ID:   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
App ID:      xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

=== GRAPH API PERMISSIONS ===
Permission              Type        Consented
----------              ----        ---------
Directory.Read.All      Application      True
RoleManagement.Read.All Application      True
AuditLog.Read.All       Application      True

=== ENTRA ID ROLES ===
Role              RoleId                               Status
----              ------                               ------
Directory Readers 88d8e3e3-8f55-4a1e-953a-9b9898b8876b Active

=== AZURE RBAC ROLES ===
RoleDefinitionName Scope
------------------ -----
Reader             /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

====================================
 PERMISSION SUMMARY
====================================
  Graph: Directory.Read.All [OK]
  Graph: RoleManagement.Read.All [OK]
  Graph: AuditLog.Read.All (optional) [OK]
  Entra Role: Directory Readers [OK]
  Azure RBAC: Reader [OK]
```

## Notes

- Uses `-DeviceCode` authentication for Azure to bypass WAM broker issues
- Uses the unified RBAC API (`Get-MgRoleManagementDirectoryRoleAssignment`) which detects PIM-assigned roles that the legacy `Get-MgDirectoryRole` API misses
- Reference: [AzureHound Azure Configuration docs](https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration)
