[README.md](https://github.com/user-attachments/files/25362353/README.md)
# 🔐 AzureHound Permission Validator

**Validates all required Azure and Entra ID permissions for AzureHound Enterprise data collection**

---

## 📋 **Overview**

This script checks that your AzureHound service principal has all the correct permissions configured in Azure and Entra ID. It validates Graph API permissions, Entra ID directory roles, and Azure RBAC roles in one quick run.

### **What It Checks**

| Check | What It Validates |
|-------|------------------|
| **Graph API Permissions** | Application-level permissions granted to the service principal |
| **Entra ID Roles** | Directory roles assigned (including PIM assignments) |
| **Azure RBAC Roles** | Subscription/resource-level role assignments |
| **Permission Summary** | PASS/FAIL status for all required and optional permissions |

### **Required Permissions It Validates**

| Permission | Type | Required |
|-----------|------|---------|
| `Directory.Read.All` | Graph API | ✅ Required |
| `RoleManagement.Read.All` | Graph API | ✅ Required |
| `AuditLog.Read.All` | Graph API | ⚠️ Optional |
| `Directory Readers` | Entra ID Role | ✅ Required |
| `Reader` | Azure RBAC | ✅ Required |

---

## ⚙️ **Requirements**

### **PowerShell Modules Required**

```powershell
# Install required modules if not already installed
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Az -Scope CurrentUser
```

### **Permissions to Run This Script**

You need an account with:
- ✅ Ability to read Azure App Registrations
- ✅ `Application.Read.All` on Microsoft Graph
- ✅ `RoleManagement.Read.Directory` on Microsoft Graph
- ✅ `Directory.Read.All` on Microsoft Graph
- ✅ Azure Reader role (to check RBAC assignments)

### **Network Requirements**
- ✅ Internet connectivity to Microsoft Graph API (`graph.microsoft.com`)
- ✅ Internet connectivity to Azure Management API (`management.azure.com`)

---

## 🚀 **Usage**

### **Method 1: Standard (Full Authentication)**

Connects to Microsoft Graph and Azure automatically using device code:

```powershell
.\AZ_Permissions-Test.ps1
```

**What happens:**
1. Opens browser for Microsoft Graph authentication
2. Opens browser for Azure authentication (device code flow)
3. Runs all permission checks
4. Displays summary

---

### **Method 2: Skip Authentication (Already Connected)**

If you have already run `Connect-AzAccount` and `az login` in your session, skip the auth step:

```powershell
.\AZ_Permissions-Test.ps1 -Skip
```

**What happens:**
1. Verifies existing Microsoft Graph session is active
2. Verifies existing Azure session is active
3. Skips re-authentication entirely
4. Runs all permission checks directly
5. Displays summary

**Use this when:**
- ✅ You already ran `Connect-AzAccount` in your current session
- ✅ You already ran `Connect-MgGraph` in your current session
- ✅ You want to re-run checks without re-authenticating
- ✅ You are in an automated pipeline with existing auth

**Pre-requisites for `-Skip`:**
```powershell
# Run these BEFORE using -Skip
Connect-MgGraph -Scopes "Application.Read.All","RoleManagement.Read.Directory","Directory.Read.All"
Connect-AzAccount
```

---

### **Method 3: Custom App Name**

Check permissions for a service principal with a different name:

```powershell
.\AZ_Permissions-Test.ps1 -AppName "MyCustomAzureHound"
```

---

### **Method 4: Specific Tenant**

Target a specific Azure tenant:

```powershell
.\AZ_Permissions-Test.ps1 -TenantId "your-tenant-id-here"
```

---

### **Combining Parameters**

```powershell
# Already connected, check specific app in specific tenant
.\AZ_Permissions-Test.ps1 -Skip -AppName "AzureHound-Prod"

# Connect fresh to specific tenant
.\AZ_Permissions-Test.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -AppName "AzureHound"
```

---

## 📊 **Example Output**

### **Standard Run**

```
====================================
 AzureHound Permission Validator
====================================
App Name:    AzureHound
Object ID:   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
App ID:      xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

=== GRAPH API PERMISSIONS ===

Permission                  Type          Consented
--------------------------  -----------   ---------
Directory.Read.All          Application   True
RoleManagement.Read.All     Application   True
AuditLog.Read.All           Application   True

=== ENTRA ID ROLES ===

Role                Scope  Status
------------------  -----  ------
Directory Readers   /      Active

=== AZURE RBAC ROLES ===

RoleDefinitionName  Scope
------------------  -----
Reader              /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

====================================
 PERMISSION SUMMARY
====================================
  Graph: Directory.Read.All          [OK]
  Graph: RoleManagement.Read.All     [OK]
  Graph: AuditLog.Read.All (optional)[OK]
  Entra Role: Directory Readers      [OK]
  Azure RBAC: Reader                 [OK]
```

---

### **With -Skip Parameter**

```
[SKIP] Authentication step bypassed - using existing session
       Assumes: Connect-AzAccount and az login already completed

Verifying existing sessions...
  [OK] Microsoft Graph session active - Account: admin@company.com
  [OK] Azure session active - Account: admin@company.com | Tenant: xxxxxxxx-xxxx

====================================
 AzureHound Permission Validator
====================================
...
```

---

### **Missing Permissions**

```
====================================
 PERMISSION SUMMARY
====================================
  Graph: Directory.Read.All          [OK]
  Graph: RoleManagement.Read.All     [MISSING]
  Graph: AuditLog.Read.All (optional)[NOT SET]
  Entra Role: Directory Readers      [OK]
  Azure RBAC: Reader                 [MISSING]
```

---

## 🛠️ **Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Skip` | Switch | `$false` | **Skip authentication** - use existing `Connect-AzAccount` / `Connect-MgGraph` session |
| `-AppName` | String | `"AzureHound"` | Name of the AzureHound service principal / Enterprise Application |
| `-TenantId` | String | _(auto-detect)_ | Azure Tenant ID to target a specific tenant |

---

## 🔍 **Troubleshooting**

### **"Service principal not found"**

```
ERROR: Service principal 'AzureHound' not found!
Make sure you have an App Registration with an associated Enterprise Application.
```

**Cause:** App Registration name doesn't match

**Solution:**
```powershell
# Find the correct name
Get-MgServicePrincipal -Filter "startswith(displayName,'Azure')" | Select DisplayName, Id

# Then run with correct name
.\AZ_Permissions-Test.ps1 -AppName "YourActualAppName"
```

---

### **"No active Microsoft Graph session" when using -Skip**

```
[WARN] No active Microsoft Graph session found
       Run: Connect-MgGraph -Scopes 'Application.Read.All','RoleManagement.Read.Directory','Directory.Read.All'
```

**Solution:**
```powershell
# Connect to Microsoft Graph first
Connect-MgGraph -Scopes "Application.Read.All","RoleManagement.Read.Directory","Directory.Read.All"

# Then re-run with -Skip
.\AZ_Permissions-Test.ps1 -Skip
```

---

### **"Could not query Azure RBAC"**

**Cause:** No active Azure session or insufficient permissions

**Solution:**
```powershell
# Re-connect to Azure
Connect-AzAccount

# Or for specific tenant
Connect-AzAccount -TenantId "your-tenant-id"

# Or run without -Skip to force fresh authentication
.\AZ_Permissions-Test.ps1
```

---

### **WAM Broker / Browser Authentication Issues**

If standard authentication hangs or shows browser errors:

```powershell
# Use -TenantId to force device code flow
.\AZ_Permissions-Test.ps1 -TenantId "your-tenant-id"
```

The script already disables WAM broker by default to prevent common authentication issues.

---

### **Module Not Found Errors**

```powershell
# Install Microsoft Graph module
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Install Azure PowerShell module
Install-Module Az -Scope CurrentUser -Force

# Verify installation
Get-Module Microsoft.Graph -ListAvailable
Get-Module Az -ListAvailable
```

---

## 📝 **Required Permissions Explained**

### **Graph API Permissions (Application)**

| Permission | Why Needed |
|-----------|-----------|
| `Directory.Read.All` | Read all users, groups, and devices in Entra ID |
| `RoleManagement.Read.All` | Read directory role assignments |
| `AuditLog.Read.All` | _(Optional)_ Read audit logs for enhanced collection |

### **Entra ID Roles**

| Role | Why Needed |
|------|-----------|
| `Directory Readers` | Read basic directory data across Entra ID |

### **Azure RBAC Roles**

| Role | Scope | Why Needed |
|------|-------|-----------|
| `Reader` | Subscription | Read Azure resources, subscriptions, and resource groups |

---

## 📚 **Reference**

- **AzureHound Installation**: https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration
- **BloodHound Enterprise**: https://bloodhound.specterops.io/
- **Microsoft Graph Permissions**: https://learn.microsoft.com/en-us/graph/permissions-reference
- **Azure RBAC Roles**: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles

---

## 🎯 **Quick Reference**

```powershell
# Fresh run - authenticate from scratch
.\AZ_Permissions-Test.ps1

# Already connected - skip auth
.\AZ_Permissions-Test.ps1 -Skip

# Custom app name
.\AZ_Permissions-Test.ps1 -AppName "MyAzureHound"

# Specific tenant
.\AZ_Permissions-Test.ps1 -TenantId "00000000-0000-0000-0000-000000000000"

# Already connected, custom app
.\AZ_Permissions-Test.ps1 -Skip -AppName "AzureHound-Prod"
```

---

**Version**: 1.0  
**Last Updated**: February 2026  
**Author**: SpecterOps BloodHound Team  
**Reference**: https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration
