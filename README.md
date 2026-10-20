# 🔐 AzureHound Permission Validator v1.5

**Validates the Microsoft Graph, Entra ID and Azure RBAC permissions AzureHound Enterprise needs for data collection**

Permissions are checked against the current SpecterOps documentation:
[AzureHound data collection permissions](https://bloodhound.specterops.io/collect-data/azurehound-data-permissions)

---

## 🆕 What's New in v1.5

| Change | Detail |
|--------|--------|
| **Least-privilege Graph permissions** | Checks the six granular permissions now documented (`User.Read.All`, `GroupMember.Read.All`, `Application.Read.All`, `Device.Read.All`, `Organization.Read.All`, `RoleManagement.Read.Directory`). `Directory.Read.All` / `RoleManagement.Read.All` still pass, flagged as broader than needed. |
| **Directory Readers no longer required** | AzureHound uses application permissions, so no Entra ID role is needed. If assigned, it's reported as removable. |
| **Tenant Root Management Group scope** | Azure RBAC must be assigned at the Tenant Root MG (ID = tenant ID). Subscription-only assignments are now reported as **MISSING**, because resources outside them are silently skipped. |
| **Custom reader role** | Recognises the documented custom `azurehound-reader-role`; built-in `Reader` still passes with an advisory. |
| **Over-privilege review** | Flags write-capable Graph permissions, Owner/Contributor RBAC roles, unused permissions and the default delegated `User.Read`. |
| **PowerShell 5.1 vs 7 guidance** | Detects the edition and prints the exact run/install commands for both. |
| **Wrong-account protection** | Graph sign-in is pinned to `-TenantId` and process-scoped; the script stops if it detects a personal Microsoft account or the wrong tenant. |
| **App lookup** | New `-AppId` parameter. If the name isn't found, lists every service principal with "hound" in the name. |
| **Fewer modules** | Only three Graph submodules are needed — not the full `Microsoft.Graph` rollup, and not Az. |
| **`-DeviceCode`** | Optional device-code sign-in for Graph (no browser / Windows account picker). |

---

## 📋 What It Checks

| Check | What It Validates |
|-------|------------------|
| **PowerShell Version** | 5.1 or 7, with run commands for each; warns if Az.Accounts is already loaded (MSAL conflict) |
| **Execution Policy** | Warns if policy may block unsigned scripts |
| **Required Modules** | Three Microsoft.Graph submodules, minimum version and matching versions |
| **Sign-in** | Work/school account in the expected tenant (not a personal MSA) |
| **Graph API Permissions** | Application permissions granted to the service principal (admin consented) |
| **Entra ID Roles** | Reported for review — none are required |
| **Azure RBAC** | Read-only role at the Tenant Root Management Group, via REST API |
| **Permission Summary** | OK / WARN / MISSING / UNKNOWN / INFO for every item |

### Required Permissions

| Permission | Type | Status | Data Collected |
|-----------|------|--------|----------------|
| `User.Read.All` | Graph (application) | ✅ Required | Users |
| `GroupMember.Read.All` | Graph (application) | ✅ Required | Groups, owners, members |
| `Application.Read.All` | Graph (application) | ✅ Required | Apps, service principals, app role assignments |
| `Device.Read.All` | Graph (application) | ✅ Required | Devices and owners |
| `Organization.Read.All` | Graph (application) | ✅ Required | Tenant information |
| `RoleManagement.Read.Directory` | Graph (application) | ✅ Required | Roles, assignments, PIM eligibility |
| `AdministrativeUnit.Read.All` | Graph (application) | ⚠️ Recommended | Admin unit details (collected, not yet processed by BloodHound) |
| `AuditLog.Read.All` | Graph (application) | ➖ Optional | Last sign-in data (needs Entra ID P1/P2) |
| `azurehound-reader-role` (custom) | Azure RBAC at **Tenant Root MG** | ✅ Required | Management groups, subscriptions, resource groups, resources, Key Vault access policies |

> `Directory.Read.All` covers the first five Graph permissions and `RoleManagement.Read.All` covers `RoleManagement.Read.Directory` — both pass, but are broader than the documented least-privilege set.
>
> Built-in `Reader` at the Tenant Root MG also works, but grants more than the custom role. The custom role JSON (`azurehound-reader-role.json`) is linked from the [SpecterOps permissions page](https://bloodhound.specterops.io/collect-data/azurehound-data-permissions).
>
> **No Entra ID directory role is required.** `Directory Readers` was needed in older guidance and can be removed if it was only assigned for AzureHound.

---

## ⚠️ Before You Run

### 1. PowerShell 7 or 5.1?

Both work. **PowerShell 7 is recommended.**

| | PowerShell 7 (`pwsh`) | Windows PowerShell 5.1 (`powershell.exe`) |
|---|---|---|
| Status | ✅ Recommended | ✅ Supported |
| Install | `winget install Microsoft.PowerShell` | Built into Windows |
| Run | `pwsh -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId '<tenant-id>'` | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId '<tenant-id>'` |
| Install modules | `Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance -Scope CurrentUser` | Run `[Net.ServicePointManager]::SecurityProtocol = 'Tls12'` first, then the same `Install-Module` command |
| Known issues | — | Microsoft.Graph and Az share one load space and can clash over the MSAL library (`Method not found ... Microsoft.Identity.Client`) |

> Modules are installed **per edition** — installing in 5.1 doesn't make them available in PowerShell 7, and vice versa.
>
> `-NoProfile` is recommended so nothing in your PowerShell profile pre-loads an older Az or Graph module.

### 2. Execution Policy

If your system uses `AllSigned` or `Restricted`, run **one** of these first:

```powershell
# RECOMMENDED - current session only, no permanent change
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# OR unblock just this file
Unblock-File -Path .\AZ_Permissions-Test.ps1

# OR inline bypass (use pwsh for PowerShell 7, powershell.exe for 5.1)
pwsh -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1
```

### 3. Required PowerShell Modules

| Module | Minimum Version |
|--------|----------------|
| `Microsoft.Graph.Authentication` | 2.0.0 |
| `Microsoft.Graph.Applications` | 2.0.0 |
| `Microsoft.Graph.Identity.Governance` | 2.0.0 |

The full `Microsoft.Graph` rollup and the **Az modules are not required** — Azure RBAC is checked via the REST API.

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance -Scope CurrentUser

# OR let the script install them for you
.\AZ_Permissions-Test.ps1 -Install
```

> After installing, open a **new** PowerShell window before running the script.

### 4. Signed-in user permissions

The account you sign in with (not the AzureHound app) needs to be able to **read**:
- Service principals and role assignments in Entra ID (e.g. Global Reader)
- Role assignments at the **Tenant Root Management Group** (e.g. Reader at the root, or elevated access). Without this, the script falls back to per-subscription checks and reports the root-scope check as **UNKNOWN**.

---

## 🚀 Quick Start

```powershell
# PowerShell 7 (recommended)
pwsh -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>"

# Windows PowerShell 5.1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>"
```

You'll be asked to sign in twice: once for Microsoft Graph, then a device code for the Azure Management API. Use the **same work account** for both.

> **Always pass `-TenantId`.** Without it, Windows may sign Graph in with a cached or personal account.

---

## 📖 Usage

### Standard run

```powershell
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>"
```

### App has a different name

```powershell
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>" -AppName "AzureHound_Prod"

# Most reliable - use the Application (client) ID
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>" -AppId "00000000-0000-0000-0000-000000000000"
```

If the name isn't found, the script lists every service principal with "hound" in its name, with the AppId to re-run with.

### Device-code sign-in for Graph (`-DeviceCode`)

Avoids the browser / Windows account picker — useful on servers, over RDP, or when the wrong account keeps being selected.

```powershell
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>" -DeviceCode
```

### Reuse existing sessions (`-Skip`)

Uses your existing `Connect-MgGraph` session, plus an Azure token from `Connect-AzAccount` or `az login`.

```powershell
Connect-MgGraph -TenantId "<tenant-id>" -Scopes "Application.Read.All","RoleManagement.Read.Directory","Directory.Read.All"
az login --tenant "<tenant-id>"
.\AZ_Permissions-Test.ps1 -Skip -TenantId "<tenant-id>"
```

| Priority | Azure token source | How you connected |
|----------|--------------------|-------------------|
| 1st | Az PowerShell | `Connect-AzAccount` |
| 2nd | Azure CLI | `az login` |
| 3rd | Neither found | RBAC check skipped, with fix options |

### Auto-install modules (`-Install`)

```powershell
.\AZ_Permissions-Test.ps1 -Install
```

---

## 🛠️ Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-TenantId` | String | _(auto-detect)_ | Tenant to check. **Recommended** — pins the Graph sign-in to this tenant |
| `-AppName` | String | `"AzureHound"` | Display name of the AzureHound service principal |
| `-AppId` | String | — | Application (client) ID — overrides `-AppName` |
| `-DeviceCode` | Switch | `$false` | Device-code sign-in for Microsoft Graph |
| `-Skip` | Switch | `$false` | Reuse existing Graph and Azure sessions |
| `-Install` | Switch | `$false` | Install missing or outdated Graph modules |

---

## 📊 Example Output

```
====================================================================
  PERMISSION SUMMARY
====================================================================

  [OK]      Graph: User.Read.All - Users
  [OK]      Graph: GroupMember.Read.All - Groups, owners, members
  [OK]      Graph: Application.Read.All - Apps, service principals, app role assignments
  [OK]      Graph: Device.Read.All - Devices and owners
  [OK]      Graph: Organization.Read.All - Tenant information
  [OK]      Graph: RoleManagement.Read.Directory - Roles, assignments, PIM eligibility
  [WARN]    Graph: AdministrativeUnit.Read.All - Recommended - in the documented least-privilege set
  [INFO]    Graph: AuditLog.Read.All (optional) - Not set - last sign-in data won't be collected (needs Entra ID P1/P2)
  [INFO]    Graph: Delegated: User.Read - Not used by AzureHound (application permissions only) - can be removed
  [OK]      Entra: no roles assigned (none required)
  [OK]      Azure RBAC: azurehound-reader-role (custom) at Tenant Root MG - Recommended setup

  RESULT: All required permissions are in place.
          1 recommendation(s) marked [WARN] above.
```

**Status key**

| Status | Meaning |
|--------|---------|
| `[OK]` | In place |
| `[WARN]` | Works, but a change is recommended (least privilege, over-privilege, missing recommended item) |
| `[MISSING]` | Required and not in place — collection will be incomplete |
| `[UNKNOWN]` | Couldn't be checked (e.g. no Azure token, or no read access at the root MG) |
| `[INFO]` | For awareness — e.g. something that can be removed |

---

## 🔍 Troubleshooting

### `This API is not supported for MSA accounts`

Graph signed in with a **personal Microsoft account**, usually a cached one picked by Windows.

```powershell
Disconnect-MgGraph
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>"          # sign in with the work account
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>" -DeviceCode   # if the wrong account keeps appearing
```

v1.5 detects this and stops with a clear message instead of reporting "service principal not found".

---

### `Method not found: ... Microsoft.Identity.Client ...`

Microsoft.Graph and Az.Accounts each ship their own copy of the MSAL sign-in library. Whichever loads first wins and the other breaks. Most common in Windows PowerShell 5.1, or when a profile pre-loads Az.

```powershell
# Fix 1 - PowerShell 7 in a clean session (recommended)
pwsh -NoProfile -File .\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>"

# Fix 2 - Windows PowerShell 5.1 in a clean session
powershell.exe -NoProfile -File .\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>"

# Diagnose - which module loaded the old MSAL?
[AppDomain]::CurrentDomain.GetAssemblies() |
  Where-Object FullName -like 'Microsoft.Identity.Client*' |
  Select-Object FullName, Location

# Fix 3 - align module versions
Update-Module Microsoft.Graph.Authentication, Az.Accounts
```

> The script itself doesn't need Az — this only bites if Az is already loaded in the session, or with `-Skip` + `Connect-AzAccount`.

---

### Nothing happens after signing in

Selecting text in the Windows console (to copy the device code) pauses the script — **QuickEdit mode**. The window title starts with "Select".

**Fix:** click the PowerShell window and press **Enter** or **Esc**. To stop it recurring, use Windows Terminal, or untick *QuickEdit Mode* in the console's Properties.

---

### Service principal not found

The app is probably named differently. The script lists candidates automatically:

```
  Service principals with 'hound' in the name:
DisplayName    AppId                                Id
-----------    -----                                --
AzureHound_Prod 00000000-0000-0000-0000-000000000000 00000000-0000-0000-0000-000000000000
```

```powershell
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>" -AppName "AzureHound_Prod"
# or
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>" -AppId "<AppId>"
```

---

### Azure RBAC: `[MISSING] Role at Tenant Root MG - Assigned only at lower scope(s)`

The role is assigned to a subscription (or lower). AzureHound **won't log an error** — it simply won't see resources outside that scope.

**Fix:** assign the custom AzureHound reader role (or Reader) at **Tenant Root Group** (Azure Portal → Management groups → Tenant Root Group → Access control (IAM)). See the [AzureHound configuration guide](https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration).

---

### Azure RBAC: `[UNKNOWN] ... could not read the root MG`

The account running the script can't read role assignments at the Tenant Root Management Group. Either:
- Grant the signed-in user Reader at the Tenant Root Group, or
- Use **Elevate access** (Entra ID → Properties → *Access management for Azure resources*) temporarily as a Global Administrator.

---

### Module install fails in Windows PowerShell 5.1

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance -Scope CurrentUser
```

---

### `Get-MgRoleManagementDirectoryRoleAssignment` not recognized

```powershell
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser -Force
# Open a new PowerShell window, then re-run
```

---

### Graph submodules on different versions

```powershell
Update-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance
```

---

## 🎯 Quick Reference

```powershell
# Recommended
pwsh -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>"

# Windows PowerShell 5.1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>"

# App named differently
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>" -AppId "<AppId>"

# Wrong account keeps being picked
.\AZ_Permissions-Test.ps1 -TenantId "<tenant-id>" -DeviceCode

# Already signed in
.\AZ_Permissions-Test.ps1 -Skip -TenantId "<tenant-id>"

# First run - install modules
.\AZ_Permissions-Test.ps1 -Install
```

---

## 📚 Reference

- **AzureHound data collection permissions**: https://bloodhound.specterops.io/collect-data/azurehound-data-permissions
- **AzureHound Azure configuration**: https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration
- **Microsoft Graph permissions reference**: https://learn.microsoft.com/en-us/graph/permissions-reference
- **Install PowerShell 7 on Windows**: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows

---

**Version**: 1.5 | **Last Updated**: October 2026 | **Author**: SpecterOps BloodHound Team
