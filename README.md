[README.md](https://github.com/user-attachments/files/25362797/README.md)
# 🔐 AzureHound Permission Validator v1.1

**Validates all required Azure and Entra ID permissions for AzureHound Enterprise data collection**

---

## 📋 **Overview**

This script checks that your AzureHound service principal has all the correct permissions configured. It validates Graph API permissions, Entra ID directory roles, and Azure RBAC roles — and now includes automatic prerequisite checks before running any tests.

### **What It Checks**

| Check | What It Validates |
|-------|------------------|
| **Execution Policy** | Warns if policy may block unsigned scripts |
| **Required Modules** | Verifies all PowerShell modules are installed and up to date |
| **Graph API Permissions** | Application permissions granted to the service principal |
| **Entra ID Roles** | Directory roles assigned (including PIM assignments) |
| **Azure RBAC Roles** | Subscription/resource-level role assignments |
| **Permission Summary** | PASS/FAIL for all required and optional permissions |

### **Required Permissions Validated**

| Permission | Type | Required |
|-----------|------|---------|
| `Directory.Read.All` | Graph API | ✅ Required |
| `RoleManagement.Read.All` | Graph API | ✅ Required |
| `AuditLog.Read.All` | Graph API | ⚠️ Optional |
| `Directory Readers` | Entra ID Role | ✅ Required |
| `Reader` | Azure RBAC | ✅ Required |

---

## ⚠️ **Before You Run - Important Notes**

### **Execution Policy Warning**

If your system uses `AllSigned` or `Restricted` execution policy, the script will be blocked. Run **one** of the following first:

```powershell
# RECOMMENDED - Bypass for current session only (no permanent change)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# OR - Unblock just this file
Unblock-File -Path .\AZ_Permissions-Test.ps1

# OR - Inline bypass
PowerShell.exe -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1
```

> The script will detect your execution policy and display these recommendations automatically if needed.

---

### **Required PowerShell Modules**

The script requires these modules to be installed:

| Module | Minimum Version | Purpose |
|--------|----------------|---------|
| `Microsoft.Graph` | 2.0.0 | Core Graph SDK |
| `Microsoft.Graph.Authentication` | 2.0.0 | Graph authentication |
| `Microsoft.Graph.Applications` | 2.0.0 | Service principal queries |
| `Microsoft.Graph.Identity.Governance` | 2.0.0 | Entra ID role queries |
| `Az.Accounts` | 2.0.0 | Azure authentication and RBAC |

> **The script will detect any missing modules and tell you exactly what to install before proceeding.**

---

## 🚀 **Quick Start**

### **Step 1 - Install Required Modules** (first time only)

```powershell
# Install everything at once
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module Az -Scope CurrentUser -Force
```

Or let the script install for you:

```powershell
.\AZ_Permissions-Test.ps1 -Install
```

> After installing, **restart PowerShell** before running the script.

---

### **Step 2 - Run the Script**

```powershell
# Standard run - authenticates from scratch
.\AZ_Permissions-Test.ps1

# Already connected? Skip auth
.\AZ_Permissions-Test.ps1 -Skip
```

---

## 📖 **Usage**

### **Method 1: Standard Run**

Connects fresh to Microsoft Graph and Azure:

```powershell
.\AZ_Permissions-Test.ps1
```

Flow:
1. ✅ Checks execution policy
2. ✅ Verifies all required modules
3. ✅ Opens browser for Microsoft Graph auth
4. ✅ Device code prompt for Azure auth
5. ✅ Runs all permission checks
6. ✅ Displays summary

---

### **Method 2: Skip Authentication** (`-Skip`)

Use if you already have active `Connect-MgGraph` and `Connect-AzAccount` sessions:

```powershell
.\AZ_Permissions-Test.ps1 -Skip
```

Pre-requisites:
```powershell
# Run these first, then use -Skip
Connect-MgGraph -Scopes "Application.Read.All","RoleManagement.Read.Directory","Directory.Read.All"
Connect-AzAccount
```

Use when:
- ✅ Re-running checks without re-authenticating
- ✅ Your session is still active
- ✅ Azure browser/WAM is causing issues

---

### **Method 3: Auto-Install Modules** (`-Install`)

Let the script install any missing modules automatically:

```powershell
.\AZ_Permissions-Test.ps1 -Install
```

> After installing, restart PowerShell and re-run without `-Install`.

---

### **Method 4: Custom App Name**

Check a service principal with a different name:

```powershell
.\AZ_Permissions-Test.ps1 -AppName "AzureHound-Production"
```

---

### **Method 5: Specific Tenant**

Target a specific Azure tenant:

```powershell
.\AZ_Permissions-Test.ps1 -TenantId "00000000-0000-0000-0000-000000000000"
```

---

### **Combining Parameters**

```powershell
# Already connected, checking a named app
.\AZ_Permissions-Test.ps1 -Skip -AppName "AzureHound-Prod"

# Fresh connect to specific tenant, auto-install if needed
.\AZ_Permissions-Test.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -Install

# Full verbose fresh run
.\AZ_Permissions-Test.ps1 -AppName "AzureHound" -TenantId "00000000-0000-0000-0000-000000000000"
```

---

## 📊 **Example Output**

### **First Run - Modules Missing**

```
====================================================================
  AzureHound Permission Validator v1.1
====================================================================

--- EXECUTION POLICY CHECK ---

  Process Scope:      Bypass
  LocalMachine Scope: AllSigned
  CurrentUser Scope:  Undefined

  [WARN] Your execution policy may block unsigned scripts

  RECOMMENDATIONS - run one of these before executing this script:

  Option 1 - Bypass for current session only (RECOMMENDED - no permanent change):
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

  Option 2 - Unblock this specific file only:
    Unblock-File -Path .\AZ_Permissions-Test.ps1

--- PREREQUISITE MODULE CHECK ---

  [MISSING]  Microsoft.Graph                              Not installed
  [MISSING]  Microsoft.Graph.Authentication               Not installed
  [MISSING]  Microsoft.Graph.Applications                 Not installed
  [MISSING]  Microsoft.Graph.Identity.Governance          Not installed
  [MISSING]  Az.Accounts                                  Not installed

  [!] One or more required modules are missing or outdated

  FIX OPTION 1 - Install everything at once (RECOMMENDED):
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
    Install-Module Az -Scope CurrentUser -Force

  FIX OPTION 3 - Let this script install everything for you:
    .\AZ_Permissions-Test.ps1 -Install

  After installing, restart PowerShell and re-run.
```

---

### **All Modules Present - Successful Run**

```
====================================================================
  AzureHound Permission Validator v1.1
====================================================================

--- EXECUTION POLICY CHECK ---

  [OK] Execution policy allows script execution

--- PREREQUISITE MODULE CHECK ---

  [OK]       Microsoft.Graph                              v2.25.0
  [OK]       Microsoft.Graph.Authentication               v2.25.0
  [OK]       Microsoft.Graph.Applications                 v2.25.0
  [OK]       Microsoft.Graph.Identity.Governance          v2.25.0
  [OK]       Az.Accounts                                  v3.0.0

  [OK] All required modules are present

--- AUTHENTICATION ---

  Connecting to Microsoft Graph (browser prompt will open)...
  [OK] Microsoft Graph connected

  Connecting to Azure (device code - check terminal for URL + code)...
  [OK] Azure connected

--- LOCATING SERVICE PRINCIPAL ---

  App Name:  AzureHound
  Object ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  App ID:    xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

=== GRAPH API PERMISSIONS ===

Permission               Type          Consented
-----------------------  -----------   ---------
Directory.Read.All       Application   True
RoleManagement.Read.All  Application   True
AuditLog.Read.All        Application   True

=== ENTRA ID ROLES ===

Role               Status
-----------------  ------
Directory Readers  Active

=== AZURE RBAC ROLES ===

RoleDefinitionName  Scope
------------------  -----
Reader              /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

====================================================================
  PERMISSION SUMMARY
====================================================================

  [OK]      Graph: Directory.Read.All
  [OK]      Graph: RoleManagement.Read.All
  [OK]      Graph: AuditLog.Read.All (optional)
  [OK]      Entra Role: Directory Readers
  [OK]      Azure RBAC: Reader

  RESULT: All required permissions are configured correctly!
```

---

## 🛠️ **Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Skip` | Switch | `$false` | Skip authentication - use existing `Connect-MgGraph` / `Connect-AzAccount` session |
| `-Install` | Switch | `$false` | Auto-install any missing or outdated required modules |
| `-AppName` | String | `"AzureHound"` | Name of the AzureHound Enterprise Application in Azure |
| `-TenantId` | String | _(auto-detect)_ | Target a specific Azure Tenant ID |

---

## 🔍 **Troubleshooting**

### **Modules Not Found After Installing**

```
Get-Module Microsoft.Graph -ListAvailable
# Returns nothing
```

**Cause:** Module was installed but PowerShell session is stale

**Fix:** Restart PowerShell completely and re-run

---

### **`Get-MgRoleManagementDirectoryRoleAssignment` Not Recognized**

**Cause:** `Microsoft.Graph.Identity.Governance` submodule not installed (common with Graph v2)

**Fix:**
```powershell
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser -Force
# Restart PowerShell, then re-run
```

---

### **Azure Credentials Expired / WAM Broker Error**

```
Method not found: 'Void Azure.Identity.Broker.SharedTokenCacheCredentialBrokerOptions..ctor'
```

**Cause:** Version conflict between Az and Azure.Identity.Broker, or expired session

**Fix:**
```powershell
# Update Az modules
Update-Module Az -Force

# Reconnect using device code (bypasses WAM broker)
$env:AZURE_USE_DEVICE_CODE = "true"
Update-AzConfig -EnableLoginByWam $false -Scope Process
Connect-AzAccount -DeviceCode

# Then re-run
.\AZ_Permissions-Test.ps1 -Skip
```

---

### **Service Principal Not Found**

```
[ERROR] Service principal 'AzureHound' not found!
```

**Fix:**
```powershell
# Find the correct name
Get-MgServicePrincipal -Filter "startswith(displayName,'Azure')" | Select DisplayName

# Re-run with correct name
.\AZ_Permissions-Test.ps1 -AppName "YourActualAppName"
```

---

### **Script Blocked by Execution Policy**

```
File cannot be loaded. The file is not digitally signed.
```

**Fix:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\AZ_Permissions-Test.ps1
```

---

## 📚 **Reference**

- **AzureHound Configuration**: https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration
- **Microsoft Graph Permissions**: https://learn.microsoft.com/en-us/graph/permissions-reference
- **Azure RBAC Built-in Roles**: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
- **PowerShell Execution Policies**: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies

---

## 🎯 **Quick Reference**

```powershell
# Install modules (first time only)
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module Az -Scope CurrentUser -Force

# OR let the script install them
.\AZ_Permissions-Test.ps1 -Install

# Standard run
.\AZ_Permissions-Test.ps1

# Already connected - skip auth
.\AZ_Permissions-Test.ps1 -Skip

# Custom app name
.\AZ_Permissions-Test.ps1 -AppName "MyAzureHound"

# Specific tenant
.\AZ_Permissions-Test.ps1 -TenantId "00000000-0000-0000-0000-000000000000"
```

---

**Version**: 1.1 | **Last Updated**: February 2026 | **Author**: SpecterOps BloodHound Team
