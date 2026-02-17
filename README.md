[README.md](https://github.com/user-attachments/files/25363226/README.md)# 🔐 AzureHound Permission Validator v1.4

**Validates all required Azure and Entra ID permissions for AzureHound Enterprise data collection**

---

## 📋 **Overview**

This script checks that your AzureHound service principal has all the correct permissions configured. It validates Graph API permissions, Entra ID directory roles, and Azure RBAC roles — and includes automatic prerequisite checks, execution policy warnings, and smart session detection.

### **What It Checks**

| Check | What It Validates |
|-------|------------------|
| **Execution Policy** | Warns if policy may block unsigned scripts |
| **Required Modules** | Verifies all Microsoft.Graph modules are installed |
| **WAM Broker** | Detects Az/Identity.Broker version conflicts (informational) |
| **Graph API Permissions** | Application permissions granted to the service principal |
| **Entra ID Roles** | Directory roles assigned (including PIM assignments) |
| **Azure RBAC Roles** | Subscription-level role assignments via REST API |
| **Permission Summary** | PASS/FAIL for all required and optional permissions |

### **Required Permissions Validated**

| Permission | Type | Status |
|-----------|------|--------|
| `Directory.Read.All` | Graph API | ✅ Required |
| `RoleManagement.Read.All` | Graph API | ✅ Required |
| `AuditLog.Read.All` | Graph API | ⚠️ Optional |
| `Directory Readers` | Entra ID Role | ✅ Required |
| `Reader` | Azure RBAC | ✅ Required |

---

## ⚠️ **Before You Run**

### **1. Execution Policy**

If your system uses `AllSigned` or `Restricted` execution policy the script will be blocked. Run **one** of the following first:

```powershell
# RECOMMENDED - current session only, no permanent change
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# OR unblock just this file
Unblock-File -Path .\AZ_Permissions-Test.ps1

# OR inline bypass
PowerShell.exe -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1
```

> The script detects your execution policy on startup and displays these options automatically if needed.

---

### **2. Required PowerShell Modules**

Only Microsoft.Graph modules are required. The Az PowerShell module is **not required** — Azure RBAC is queried via REST API directly, which also avoids WAM broker issues entirely.

| Module | Minimum Version |
|--------|----------------|
| `Microsoft.Graph` | 2.0.0 |
| `Microsoft.Graph.Authentication` | 2.0.0 |
| `Microsoft.Graph.Applications` | 2.0.0 |
| `Microsoft.Graph.Identity.Governance` | 2.0.0 |

```powershell
# Install all at once
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# OR let the script install them for you
.\AZ_Permissions-Test.ps1 -Install
```

> After installing, **restart PowerShell** before running the script.

---

## 🚀 **Quick Start**

```powershell
# Step 1 - Install modules (first time only)
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Step 2 - Restart PowerShell, then run
.\AZ_Permissions-Test.ps1
```

---

## 📖 **Usage**

### **Method 1: Standard Run**

Authenticates fresh from scratch. Opens browser for Microsoft Graph, then prompts for Azure device code:

```powershell
.\AZ_Permissions-Test.ps1
```

---

### **⚡ Method 2: Skip Authentication (`-Skip`)**

**Use this if you are already connected to Azure** — the script will pick up your existing session automatically.

```powershell
.\AZ_Permissions-Test.ps1 -Skip
```

**The `-Skip` flag checks 3 token sources in order:**

| Priority | Source | How You Connected |
|----------|--------|------------------|
| 1st | **Az PowerShell** | `Connect-AzAccount` |
| 2nd | **Azure CLI** | `az login` |
| 3rd | Neither found | Displays fix options |

**Example — already connected via `az login`:**
```
  Checking for existing Azure token...
  [OK] Azure token from Azure CLI (az login) - Account: user@company.com
```

**Example — already connected via `Connect-AzAccount`:**
```
  Checking for existing Azure token...
  [OK] Azure token from Az PowerShell - Account: user@company.com
```

**No active session found:**
```
  [WARN] No active Azure session found

  RBAC check will be skipped. To fix, run ONE of these then retry with -Skip:

  Option A - Azure PowerShell:
    Connect-AzAccount -DeviceCode

  Option B - Azure CLI:
    az login

  Option C - Provide Tenant ID and re-authenticate:
    .\AZ_Permissions-Test.ps1 -TenantId 'your-tenant-id-here'
```

> **Note:** `-Skip` also bypasses the Microsoft Graph login prompt — your existing `Connect-MgGraph` session is used. If no Graph session is found, it will warn you with the exact command to fix it.

---

### **Method 3: Auto-Install Modules (`-Install`)**

Automatically installs any missing or outdated modules:

```powershell
.\AZ_Permissions-Test.ps1 -Install
```

> Restart PowerShell after installing, then re-run without `-Install`.

---

### **Method 4: Custom App Name**

If your AzureHound Enterprise Application is named differently:

```powershell
.\AZ_Permissions-Test.ps1 -AppName "AzureHound-Production"
```

Find the correct name if unsure:
```powershell
Get-MgServicePrincipal -Filter "startswith(displayName,'Azure')" | Select DisplayName
```

---

### **Method 5: Specific Tenant**

Target a specific Azure tenant (also used when no tenant can be auto-detected):

```powershell
.\AZ_Permissions-Test.ps1 -TenantId "00000000-0000-0000-0000-000000000000"
```

---

### **Combining Parameters**

```powershell
# Already connected, checking a differently-named app
.\AZ_Permissions-Test.ps1 -Skip -AppName "AzureHound-Prod"

# Fresh connect to a specific tenant
.\AZ_Permissions-Test.ps1 -TenantId "00000000-0000-0000-0000-000000000000"

# Already connected, specific tenant
.\AZ_Permissions-Test.ps1 -Skip -TenantId "00000000-0000-0000-0000-000000000000"
```

---

## 🛠️ **Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Skip` | Switch | `$false` | Use existing session — detects `Connect-AzAccount` or `az login` automatically |
| `-Install` | Switch | `$false` | Auto-install missing or outdated Microsoft.Graph modules |
| `-AppName` | String | `"AzureHound"` | Name of the AzureHound service principal in Azure |
| `-TenantId` | String | _(auto-detect)_ | Target a specific Azure Tenant ID |

---

## 📊 **Example Output**

### **Full Successful Run with -Skip**

```
====================================================================
  AzureHound Permission Validator v1.4
====================================================================

--- EXECUTION POLICY CHECK ---
  [OK] Execution policy allows script execution

--- PREREQUISITE MODULE CHECK ---
  [OK]       Microsoft.Graph                              v2.25.0
  [OK]       Microsoft.Graph.Authentication               v2.25.0
  [OK]       Microsoft.Graph.Applications                 v2.25.0
  [OK]       Microsoft.Graph.Identity.Governance          v2.25.0

  [OK] All required modules are present

--- WAM BROKER COMPATIBILITY CHECK ---
  Az.Accounts:           Not installed (not required - RBAC uses REST API)
  Azure.Identity.Broker: Not installed
  [OK] WAM broker conflict not applicable

--- AUTHENTICATION ---
  [SKIP] Bypassing authentication - using existing session

  Verifying existing sessions...
  [OK] Microsoft Graph - Account: admin@company.com
  Checking for existing Azure token...
  [OK] Azure token from Azure CLI (az login) - Account: admin@company.com

--- LOCATING SERVICE PRINCIPAL: 'AzureHound' ---
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
  Found 1 subscription(s)

  RoleDefinitionName  Scope                                        Subscription
  ------------------  -----                                        ------------
  Reader              /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx       Production

====================================================================
  PERMISSION SUMMARY
====================================================================

  [OK]      Graph: Directory.Read.All
  [OK]      Graph: RoleManagement.Read.All
  [OK]      Graph: AuditLog.Read.All (optional)
  [OK]      Entra Role: Directory Readers
  [OK]      Azure RBAC: Reader

  RESULT: All required permissions are configured correctly!
====================================================================
```

---

## 🔍 **Troubleshooting**

### **RBAC shows [SKIP] - No Azure token**

The script couldn't find an active Azure session.

**Fix:**
```powershell
# Option A - Azure CLI (simplest)
az login
.\AZ_Permissions-Test.ps1 -Skip

# Option B - Az PowerShell
Connect-AzAccount -DeviceCode
.\AZ_Permissions-Test.ps1 -Skip

# Option C - Fresh run (no -Skip needed)
.\AZ_Permissions-Test.ps1
```

---

### **Script blocked by execution policy**

```
File cannot be loaded. The file is not digitally signed.
```

**Fix:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\AZ_Permissions-Test.ps1
```

---

### **Microsoft.Graph modules missing**

```
[MISSING] Microsoft.Graph    Not installed
```

**Fix:**
```powershell
# Auto-install
.\AZ_Permissions-Test.ps1 -Install

# OR manually
Install-Module Microsoft.Graph -Scope CurrentUser -Force
# Restart PowerShell, then re-run
```

---

### **`Get-MgRoleManagementDirectoryRoleAssignment` not recognized**

Microsoft.Graph v2 moved this cmdlet to a sub-module.

**Fix:**
```powershell
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser -Force
# Restart PowerShell, then re-run
```

---

### **Service principal not found**

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

### **Tenant ID not detected**

If the script can't auto-detect your tenant:

```powershell
# Find your tenant ID
az account show --query tenantId
(Get-AzContext).Tenant.Id

# Pass it directly
.\AZ_Permissions-Test.ps1 -TenantId "your-tenant-id"
```

---

## 🎯 **Quick Reference**

```powershell
# Already logged in (az login or Connect-AzAccount)
.\AZ_Permissions-Test.ps1 -Skip

# Fresh authentication from scratch
.\AZ_Permissions-Test.ps1

# First time - install modules first
.\AZ_Permissions-Test.ps1 -Install

# Custom app name
.\AZ_Permissions-Test.ps1 -AppName "AzureHound-Prod"

# Specific tenant
.\AZ_Permissions-Test.ps1 -TenantId "00000000-0000-0000-0000-000000000000"

# Already connected + custom app
.\AZ_Permissions-Test.ps1 -Skip -AppName "AzureHound-Prod"
```

---

## 📚 **Reference**

- **AzureHound Configuration**: https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration
- **Microsoft Graph Permissions**: https://learn.microsoft.com/en-us/graph/permissions-reference
- **Azure RBAC Built-in Roles**: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles

---

**Version**: 1.4 | **Last Updated**: February 2026 | **Author**: SpecterOps BloodHound Team

