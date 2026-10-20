# ===================================================================
# AzureHound Permission Validator v1.5
# Checks the permissions AzureHound Enterprise needs for data collection
# Permission reference: https://bloodhound.specterops.io/collect-data/azurehound-data-permissions
# Setup guide:          https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration
# ===================================================================

param(
    [string]$AppName  = "AzureHound",
    [string]$AppId    = "",        # Client (application) ID - more reliable than the display name
    [string]$TenantId = "",        # Strongly recommended - stops Graph signing in to the wrong tenant / a personal account
    [switch]$DeviceCode,           # Use device code for the Microsoft Graph sign-in (no browser / account picker)
    [switch]$Skip,                 # Reuse existing Connect-MgGraph / Connect-AzAccount / az login sessions
    [switch]$Install               # Auto-install any missing required modules
)

$ScriptVersion    = "1.5"
$ConsumerTenantId = "9188040d-6c67-4c5b-b112-36a304b66dad"   # Personal Microsoft account (MSA) tenant
$GraphAppId       = "00000003-0000-0000-c000-000000000000"   # Microsoft Graph first-party app

# ===================================================================
# WAM BROKER FIX - MUST BE FIRST - before ANY Az module is touched
# ===================================================================

$env:AZURE_USE_DEVICE_CODE    = "true"
$env:AZURE_CLIENTS_USE_BROKER = "false"

try {
    if (Get-Command Update-AzConfig -ErrorAction SilentlyContinue) {
        Update-AzConfig -EnableLoginByWam $false -Scope Process -ErrorAction SilentlyContinue | Out-Null
    }
} catch { <# Non-fatal - env vars above are the primary fix #> }

# ===================================================================
# BANNER
# ===================================================================

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  AzureHound Permission Validator v$ScriptVersion" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

# ===================================================================
# SECTION 1: POWERSHELL VERSION CHECK
# ===================================================================

Write-Host "--- POWERSHELL VERSION CHECK ---" -ForegroundColor White
Write-Host ""

$psVer   = $PSVersionTable.PSVersion
$isCore  = $PSVersionTable.PSEdition -eq "Core"
$psExe   = if ($isCore) { "pwsh" } else { "powershell.exe" }
$tenantHint = if ($TenantId) { $TenantId } else { "<tenant-id>" }

Write-Host ("  Running: PowerShell {0} ({1})" -f $psVer, $(if ($isCore) { "PowerShell 7 / Core" } else { "Windows PowerShell 5.1 / Desktop" })) -ForegroundColor Gray
Write-Host ""

if ($isCore) {
    if ($psVer -lt [version]"7.2") {
        Write-Host "  [WARN] PowerShell $psVer is out of support - update to 7.4 or later:" -ForegroundColor Yellow
        Write-Host "           winget upgrade Microsoft.PowerShell" -ForegroundColor White
    } else {
        Write-Host "  [OK] PowerShell 7 (recommended)" -ForegroundColor Green
    }
} else {
    Write-Host "  [INFO] Windows PowerShell 5.1 is supported, but PowerShell 7 is recommended:" -ForegroundColor Cyan
    Write-Host "         - 5.1 loads every module into one shared space, so Microsoft.Graph and Az" -ForegroundColor DarkGray
    Write-Host "           can clash over the MSAL sign-in library ('Method not found ... Identity.Client')" -ForegroundColor DarkGray
    Write-Host "         - 5.1 needs TLS 1.2 forced on to install modules from the PowerShell Gallery" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Install PowerShell 7:   winget install Microsoft.PowerShell" -ForegroundColor White
}
Write-Host ""
Write-Host "  How to run this script:" -ForegroundColor Cyan
Write-Host "    PowerShell 7:    pwsh -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId '$tenantHint'" -ForegroundColor White
Write-Host "    PowerShell 5.1:  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId '$tenantHint'" -ForegroundColor White
Write-Host ""

# MSAL conflict: if Az.Accounts is already loaded in this session, Graph sign-in can break
if (Get-Module -Name Az.Accounts) {
    Write-Host "  [WARN] Az.Accounts is already loaded in this PowerShell session." -ForegroundColor Yellow
    Write-Host "         It can clash with Microsoft.Graph over the MSAL sign-in library." -ForegroundColor DarkGray
    Write-Host "         If sign-in fails with 'Method not found', open a NEW window and use -NoProfile (commands above)." -ForegroundColor DarkGray
    Write-Host ""
}

# ===================================================================
# SECTION 2: EXECUTION POLICY CHECK
# ===================================================================

Write-Host "--- EXECUTION POLICY CHECK ---" -ForegroundColor White
Write-Host ""

$processPol = Get-ExecutionPolicy -Scope Process
$machinePol = Get-ExecutionPolicy -Scope LocalMachine
$userPol    = Get-ExecutionPolicy -Scope CurrentUser

Write-Host ("  Process Scope:      {0}" -f $processPol) -ForegroundColor Gray
Write-Host ("  LocalMachine Scope: {0}" -f $machinePol) -ForegroundColor Gray
Write-Host ("  CurrentUser Scope:  {0}" -f $userPol)    -ForegroundColor Gray
Write-Host ""

$restrictedPolicies = @("Restricted", "AllSigned")
if ($machinePol -in $restrictedPolicies -or $userPol -in $restrictedPolicies) {
    Write-Host "  [WARN] Your execution policy may block unsigned scripts" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  RECOMMENDATIONS - run ONE of these before executing this script:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Option 1 - Bypass for current session only (RECOMMENDED - no permanent change):" -ForegroundColor Cyan
    Write-Host "    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process" -ForegroundColor White
    Write-Host ""
    Write-Host "  Option 2 - Unblock this specific file only:" -ForegroundColor Cyan
    Write-Host "    Unblock-File -Path .\AZ_Permissions-Test.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "  Option 3 - Inline bypass (no changes required):" -ForegroundColor Cyan
    Write-Host "    $psExe -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "  [OK] Execution policy allows script execution" -ForegroundColor Green
    Write-Host ""
}

# ===================================================================
# SECTION 3: PREREQUISITE MODULE CHECK
# Only three Graph submodules are needed. The full Microsoft.Graph rollup and the
# Az modules are NOT required (RBAC is checked via the Azure REST API).
# ===================================================================

Write-Host "--- PREREQUISITE MODULE CHECK ---" -ForegroundColor White
Write-Host ""

$prereqsPassed  = $true
$missingModules = @()
$foundVersions  = @()

$requiredModules = @(
    @{ Name = "Microsoft.Graph.Authentication";      MinVersion = "2.0.0" },
    @{ Name = "Microsoft.Graph.Applications";        MinVersion = "2.0.0" },
    @{ Name = "Microsoft.Graph.Identity.Governance"; MinVersion = "2.0.0" }
)

foreach ($mod in $requiredModules) {
    $installed = Get-Module -Name $mod.Name -ListAvailable |
                 Sort-Object Version -Descending |
                 Select-Object -First 1

    if ($installed) {
        $foundVersions += $installed.Version
        if ($installed.Version -ge [version]$mod.MinVersion) {
            Write-Host ("  [OK]       {0,-45} v{1}" -f $mod.Name, $installed.Version) -ForegroundColor Green
        } else {
            Write-Host ("  [OUTDATED] {0,-45} v{1} (need {2}+)" -f $mod.Name, $installed.Version, $mod.MinVersion) -ForegroundColor Yellow
            $missingModules += $mod
            $prereqsPassed = $false
        }
    } else {
        Write-Host ("  [MISSING]  {0,-45} Not installed" -f $mod.Name) -ForegroundColor Red
        $missingModules += $mod
        $prereqsPassed = $false
    }
}

Write-Host ""

if (-not $prereqsPassed) {

    Write-Host "  [!] One or more required modules are missing or outdated" -ForegroundColor Red
    Write-Host ""

    if ($Install) {
        if (-not $isCore) {
            # Windows PowerShell 5.1 defaults to older TLS versions that the PowerShell Gallery rejects
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        Write-Host "  [-Install] Installing missing/outdated modules now..." -ForegroundColor Yellow
        Write-Host ""
        foreach ($mod in $missingModules) {
            Write-Host "  Installing $($mod.Name)..." -ForegroundColor Cyan
            try {
                Install-Module -Name $mod.Name -Scope CurrentUser -MinimumVersion $mod.MinVersion `
                    -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
                Write-Host "  [OK] $($mod.Name) installed" -ForegroundColor Green
            }
            catch {
                Write-Host "  [FAIL] $($mod.Name) - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Write-Host ""
        Write-Host "  Installation complete." -ForegroundColor Green
        Write-Host "  Please open a NEW PowerShell window and re-run the script to load the new modules." -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    else {
        $modList = ($requiredModules | ForEach-Object { $_.Name }) -join ", "
        Write-Host "  FIX OPTION 1 - Install the required Graph modules:" -ForegroundColor Cyan
        if (-not $isCore) {
            Write-Host "    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'   # Windows PowerShell 5.1 only" -ForegroundColor White
        }
        Write-Host "    Install-Module $modList -Scope CurrentUser -Repository PSGallery -Force" -ForegroundColor White
        Write-Host ""
        Write-Host "  FIX OPTION 2 - Let this script install them for you:" -ForegroundColor Cyan
        Write-Host "    .\AZ_Permissions-Test.ps1 -Install" -ForegroundColor White
        Write-Host ""
        Write-Host "  After installing, open a NEW PowerShell window and re-run." -ForegroundColor Yellow
        Write-Host "  NOTE: modules install per edition - installing in 5.1 does not install for PowerShell 7, and vice versa." -ForegroundColor DarkGray
        Write-Host ""
        exit 1
    }
}

# Mismatched Graph submodule versions are a common cause of odd cmdlet / assembly errors
$distinctVers = $foundVersions | Sort-Object -Unique
if (@($distinctVers).Count -gt 1) {
    Write-Host "  [WARN] Microsoft.Graph submodules are on different versions ($($distinctVers -join ', '))" -ForegroundColor Yellow
    Write-Host "         Mismatched versions can cause load errors. Align them with:" -ForegroundColor DarkGray
    Write-Host "           Update-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance" -ForegroundColor White
    Write-Host ""
}

Write-Host "  [OK] All required modules are present" -ForegroundColor Green
Write-Host ""

# ===================================================================
# SECTION 4: IMPORT SUBMODULES (pinned to the same version where possible)
# ===================================================================

$importModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Identity.Governance"
)

foreach ($mod in $importModules) {
    try {
        Import-Module $mod -ErrorAction Stop
    }
    catch {
        Write-Host "  [WARN] Could not import $mod : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ===================================================================
# HELPER: validate the Graph context is a work/school account in the right tenant
# ===================================================================

function Test-GraphContext {
    param($Context, [string]$ExpectedTenant)

    if (-not $Context) {
        Write-Host "  [FAIL] No Microsoft Graph session found" -ForegroundColor Red
        return $false
    }
    if ($Context.TenantId -eq $ConsumerTenantId -or $Context.Account -match '@(outlook|hotmail|live|msn)\.') {
        Write-Host "  [FAIL] Graph is signed in with a PERSONAL Microsoft account: $($Context.Account)" -ForegroundColor Red
        Write-Host "         Directory APIs are not available to personal accounts ('not supported for MSA accounts')." -ForegroundColor DarkGray
        Write-Host "         Fix: Disconnect-MgGraph, then re-run with -TenantId and sign in with a work/school account." -ForegroundColor White
        return $false
    }
    if ($ExpectedTenant -and $ExpectedTenant -match '^[0-9a-fA-F-]{36}$' -and $Context.TenantId -ne $ExpectedTenant) {
        Write-Host "  [FAIL] Graph is signed in to tenant $($Context.TenantId), not the requested $ExpectedTenant" -ForegroundColor Red
        Write-Host "         Fix: Disconnect-MgGraph, then re-run with -TenantId '$ExpectedTenant'." -ForegroundColor White
        return $false
    }
    Write-Host "  [OK] Microsoft Graph - Account: $($Context.Account)  Tenant: $($Context.TenantId)" -ForegroundColor Green
    return $true
}

function Write-QuickEditHint {
    Write-Host "  TIP: if nothing happens after you finish signing in, click this window and press Enter." -ForegroundColor DarkGray
    Write-Host "       Selecting text to copy the code pauses the console (Windows QuickEdit mode)." -ForegroundColor DarkGray
}

# ===================================================================
# SECTION 5: AUTHENTICATION
# ===================================================================

Write-Host "--- AUTHENTICATION ---" -ForegroundColor White
Write-Host ""

if (-not $TenantId) {
    Write-Host "  [INFO] No -TenantId supplied. If Windows picks the wrong (or a personal) account," -ForegroundColor Cyan
    Write-Host "         re-run with -TenantId '<tenant-id>' to force the right tenant." -ForegroundColor DarkGray
    Write-Host ""
}

$script:azToken    = $null
$script:azTenantId = $TenantId

if ($Skip) {
    Write-Host "  [SKIP] Bypassing authentication - using existing session" -ForegroundColor Yellow
    Write-Host ""

    $mgContext = $null
    try { $mgContext = Get-MgContext -ErrorAction Stop } catch { }
    if (-not (Test-GraphContext -Context $mgContext -ExpectedTenant $TenantId)) {
        Write-Host "         Run: Connect-MgGraph -TenantId '<tenant-id>' -Scopes 'Application.Read.All','RoleManagement.Read.Directory','Directory.Read.All'" -ForegroundColor DarkGray
        Write-Host ""
        exit 1
    }
    if (-not $script:azTenantId) { $script:azTenantId = $mgContext.TenantId }

    # ---------------------------------------------------------------
    # Azure token - try 2 sources in order:
    #   1. Az PowerShell (Get-AzAccessToken) - if Connect-AzAccount was used
    #   2. Azure CLI     (az account get-access-token) - if az login was used
    # ---------------------------------------------------------------
    Write-Host "  Checking for existing Azure token..." -ForegroundColor Cyan

    try {
        $azContext = Get-AzContext -ErrorAction Stop
        if ($azContext -and $azContext.Account) {
            $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
            $tok = $tokenObj.Token
            if ($tok -is [System.Security.SecureString]) {
                # Az.Accounts 5+ returns a SecureString
                $tok = [System.Net.NetworkCredential]::new("", $tok).Password
            }
            $script:azToken = $tok
            Write-Host "  [OK] Azure token from Az PowerShell - Account: $($azContext.Account)" -ForegroundColor Green
        }
    }
    catch { <# MSAL/WAM conflict or no session - try next source #> }

    if (-not $script:azToken) {
        try {
            $null = Get-Command az -ErrorAction Stop
            $azArgs = @("account", "get-access-token", "--resource", "https://management.azure.com/")
            if ($script:azTenantId) { $azArgs += @("--tenant", $script:azTenantId) }
            $azCliToken = & az @azArgs 2>$null | ConvertFrom-Json -ErrorAction Stop
            if ($azCliToken -and $azCliToken.accessToken) {
                $script:azToken = $azCliToken.accessToken
                Write-Host "  [OK] Azure token from Azure CLI (az login)" -ForegroundColor Green
            }
        }
        catch { <# Azure CLI not installed or not logged in #> }
    }

    if (-not $script:azToken) {
        Write-Host "  [WARN] No active Azure session found - RBAC check will be skipped." -ForegroundColor Yellow
        Write-Host "         Fix: re-run WITHOUT -Skip (the script signs in to Azure itself, no Az module needed)," -ForegroundColor DarkGray
        Write-Host "         or run 'az login --tenant <tenant-id>' and retry with -Skip." -ForegroundColor DarkGray
    }
    Write-Host ""
}
else {
    # ---------------------------------------------------------------
    # Microsoft Graph - tenant-pinned, process-scoped (avoids reusing a cached personal account)
    # ---------------------------------------------------------------
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    $mgParams = @{
        Scopes       = "Application.Read.All", "RoleManagement.Read.Directory", "Directory.Read.All"
        NoWelcome    = $true
        ContextScope = "Process"
        ErrorAction  = "Stop"
    }
    if ($TenantId)   { $mgParams.TenantId = $TenantId }
    if ($DeviceCode) { $mgParams.UseDeviceCode = $true }

    if ($DeviceCode) {
        Write-Host "  Connecting to Microsoft Graph (device code)..." -ForegroundColor Cyan
        Write-QuickEditHint
    } else {
        Write-Host "  Connecting to Microsoft Graph (sign-in window will open - use -DeviceCode if it does not)..." -ForegroundColor Cyan
    }

    try {
        Connect-MgGraph @mgParams
    }
    catch {
        Write-Host "  [FAIL] Microsoft Graph connection failed: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Message -like "*Method not found*") {
            Write-Host "         MSAL library conflict - open a NEW window and run with -NoProfile:" -ForegroundColor Yellow
            Write-Host "           $psExe -NoProfile -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1 -TenantId '$tenantHint'" -ForegroundColor White
        }
        exit 1
    }

    $mgContext = Get-MgContext
    if (-not (Test-GraphContext -Context $mgContext -ExpectedTenant $TenantId)) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        exit 1
    }
    if (-not $script:azTenantId) { $script:azTenantId = $mgContext.TenantId }

    Write-Host ""

    # ---------------------------------------------------------------
    # Azure Resource Manager - REST device code (no Az module, no WAM, no MSAL conflict)
    # ---------------------------------------------------------------
    Write-Host "  Connecting to Azure Management API (device code)..." -ForegroundColor Cyan
    Write-Host "  NOTE: Uses the REST API directly - no Az module required" -ForegroundColor DarkGray
    Write-QuickEditHint
    Write-Host ""

    try {
        $azCliClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Azure CLI public client ID
        $deviceCodeResponse = Invoke-RestMethod `
            -Method POST `
            -Uri    "https://login.microsoftonline.com/$($script:azTenantId)/oauth2/v2.0/devicecode" `
            -Body   @{
                client_id = $azCliClientId
                scope     = "https://management.azure.com/.default offline_access"
            } -ErrorAction Stop

        Write-Host "  $($deviceCodeResponse.message)" -ForegroundColor Yellow
        Write-Host ""

        $tokenBody = @{
            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
            client_id   = $azCliClientId
            device_code = $deviceCodeResponse.device_code
        }

        $expiry    = (Get-Date).AddSeconds($deviceCodeResponse.expires_in)
        $interval  = [int]$deviceCodeResponse.interval
        $tokenData = $null

        Write-Host "  Waiting for authentication..." -ForegroundColor Cyan

        while ((Get-Date) -lt $expiry) {
            Start-Sleep -Seconds $interval
            try {
                $tokenData = Invoke-RestMethod `
                    -Method POST `
                    -Uri    "https://login.microsoftonline.com/$($script:azTenantId)/oauth2/v2.0/token" `
                    -Body   $tokenBody -ErrorAction Stop
                break
            } catch {
                $errDetail = $null
                try { $errDetail = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop } catch { }
                if     ($errDetail.error -eq "authorization_pending") { continue }
                elseif ($errDetail.error -eq "slow_down")             { $interval += 5; continue }
                elseif ($errDetail.error -eq "expired_token")         { break }
                else { throw }
            }
        }

        if ($tokenData -and $tokenData.access_token) {
            $script:azToken = $tokenData.access_token
            Write-Host "  [OK] Azure Management API token acquired" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] Azure authentication timed out - RBAC check will be skipped" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [WARN] Azure authentication failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "         RBAC checks will be skipped" -ForegroundColor DarkGray
    }

    Write-Host ""
}

# Tenant GUID (needed for the Tenant Root Management Group scope)
$tenantGuid = $mgContext.TenantId

# ===================================================================
# SECTION 6: LOCATE SERVICE PRINCIPAL
# ===================================================================

$lookupLabel = if ($AppId) { "AppId '$AppId'" } else { "name '$AppName'" }
Write-Host "--- LOCATING SERVICE PRINCIPAL: $lookupLabel ---" -ForegroundColor White
Write-Host ""

try {
    if ($AppId) {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction Stop
    } else {
        $sp = Get-MgServicePrincipal -Filter "displayName eq '$AppName'" -ErrorAction Stop
    }
}
catch {
    Write-Host "  [ERROR] Service principal lookup failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}

if (-not $sp) {
    Write-Host "  [ERROR] No service principal with $lookupLabel found in tenant $tenantGuid" -ForegroundColor Red
    Write-Host ""

    $candidates = $null
    try {
        $candidates = Get-MgServicePrincipal -Search '"displayName:hound"' -ConsistencyLevel eventual -All -ErrorAction Stop
    } catch { }

    if ($candidates) {
        Write-Host "  Service principals with 'hound' in the name:" -ForegroundColor Yellow
        $candidates | Select-Object DisplayName, AppId, Id | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
        Write-Host "  Re-run with one of these:" -ForegroundColor Yellow
        Write-Host "    .\AZ_Permissions-Test.ps1 -TenantId '$tenantGuid' -AppName '<DisplayName>'" -ForegroundColor White
        Write-Host "    .\AZ_Permissions-Test.ps1 -TenantId '$tenantGuid' -AppId '<AppId>'" -ForegroundColor White
    } else {
        Write-Host "  No service principals with 'hound' in the name were found either." -ForegroundColor Yellow
        Write-Host "  Check Entra ID > Enterprise applications (Application type: All applications)," -ForegroundColor Gray
        Write-Host "  then re-run with -AppId '<Application (client) ID>'." -ForegroundColor Gray
    }
    Write-Host ""
    exit 1
}

if (@($sp).Count -gt 1) {
    Write-Host "  [WARN] $(@($sp).Count) service principals match $lookupLabel - using the first. Use -AppId to be specific." -ForegroundColor Yellow
    $sp = @($sp)[0]
}

Write-Host "  App Name:  $($sp.DisplayName)" -ForegroundColor White
Write-Host "  Object ID: $($sp.Id)"           -ForegroundColor Gray
Write-Host "  App ID:    $($sp.AppId)"        -ForegroundColor Gray
Write-Host "  Tenant:    $tenantGuid"          -ForegroundColor Gray
Write-Host ""

# Results collected for the summary: Status = OK | WARN | MISSING | UNKNOWN | INFO
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string]$Status, [string]$Area, [string]$Item, [string]$Note = "", [bool]$Blocking = $false) {
    $results.Add([PSCustomObject]@{ Status = $Status; Area = $Area; Item = $Item; Note = $Note; Blocking = $Blocking })
}

# ===================================================================
# SECTION 7: GRAPH API PERMISSIONS (application permissions only)
# ===================================================================

Write-Host "=== GRAPH API PERMISSIONS ===" -ForegroundColor Cyan

$graphPerms  = $null
$msgraph     = $null
$graphQueryOk = $false
try {
    $msgraph = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" -ErrorAction Stop
    $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction Stop |
                          Where-Object { $_.ResourceId -eq $msgraph.Id }

    $graphPerms = @(foreach ($a in $appRoleAssignments) {
        $role = $msgraph.AppRoles | Where-Object { $_.Id -eq $a.AppRoleId }
        if ($role) {
            [PSCustomObject]@{ Permission = $role.Value; Type = "Application"; Consented = $true }
        }
    })
    $graphQueryOk = $true

    if ($graphPerms.Count -gt 0) {
        $graphPerms | Sort-Object Permission | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
    } else {
        Write-Host "  No Graph application permissions granted (admin consent may be missing)." -ForegroundColor Yellow
        Write-Host ""
    }
}
catch {
    Write-Host "  [ERROR] Could not query Graph permissions: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

$granted = @($graphPerms | ForEach-Object { $_.Permission })

# Least-privilege permissions from the AzureHound docs, with the broader permissions that also satisfy them
$graphRequired = @(
    @{ Perm = "User.Read.All";                 Broader = @("Directory.Read.All");      Data = "Users" },
    @{ Perm = "GroupMember.Read.All";          Broader = @("Directory.Read.All");      Data = "Groups, owners, members" },
    @{ Perm = "Application.Read.All";          Broader = @("Directory.Read.All");      Data = "Apps, service principals, app role assignments" },
    @{ Perm = "Device.Read.All";               Broader = @("Directory.Read.All");      Data = "Devices and owners" },
    @{ Perm = "Organization.Read.All";         Broader = @("Directory.Read.All");      Data = "Tenant information" },
    @{ Perm = "RoleManagement.Read.Directory"; Broader = @("RoleManagement.Read.All"); Data = "Roles, assignments, PIM eligibility" }
)

if ($graphQueryOk) {
    foreach ($r in $graphRequired) {
        if ($granted -contains $r.Perm) {
            Add-Result "OK" "Graph" $r.Perm $r.Data
        } else {
            $via = $r.Broader | Where-Object { $granted -contains $_ } | Select-Object -First 1
            if ($via) {
                Add-Result "OK" "Graph" $r.Perm "via $via (broader than needed)"
            } else {
                Add-Result "MISSING" "Graph" $r.Perm $r.Data $true
            }
        }
    }

    # AdministrativeUnit.Read.All - listed in the least-privilege set; collected but not yet processed by BloodHound
    if ($granted -contains "AdministrativeUnit.Read.All") {
        Add-Result "OK" "Graph" "AdministrativeUnit.Read.All" "Admin unit details (collected, not yet processed by BloodHound)"
    } elseif ($granted -contains "Directory.Read.All") {
        Add-Result "OK" "Graph" "AdministrativeUnit.Read.All" "via Directory.Read.All (broader than needed)"
    } else {
        Add-Result "WARN" "Graph" "AdministrativeUnit.Read.All" "Recommended - in the documented least-privilege set"
    }

    # Optional
    if ($granted -contains "AuditLog.Read.All") {
        Add-Result "OK" "Graph" "AuditLog.Read.All (optional)" "Last sign-in data (needs Entra ID P1/P2)"
    } else {
        Add-Result "INFO" "Graph" "AuditLog.Read.All (optional)" "Not set - last sign-in data won't be collected (needs Entra ID P1/P2)"
    }

    # Over-privilege review
    $knownPerms = @($graphRequired | ForEach-Object { $_.Perm }) +
                  @("AdministrativeUnit.Read.All", "AuditLog.Read.All", "Directory.Read.All", "RoleManagement.Read.All")
    foreach ($p in $granted) {
        if ($p -match '(?i)ReadWrite|FullControl|\.Write(\.|$)|\.Send(\.|$)|\.Manage(\.|$)') {
            Add-Result "WARN" "Graph" $p "Write/privileged permission - AzureHound only needs read access; remove it"
        } elseif ($knownPerms -notcontains $p) {
            Add-Result "INFO" "Graph" $p "Not used by AzureHound - can be removed"
        }
    }
    if ($granted -contains "Directory.Read.All" -or $granted -contains "RoleManagement.Read.All") {
        Add-Result "INFO" "Graph" "Least privilege" "Directory.Read.All / RoleManagement.Read.All work, but the granular permissions above are the documented least-privilege set"
    }
} else {
    Add-Result "UNKNOWN" "Graph" "Application permissions" "Query failed - see errors above" $true
}

# Delegated permissions on the app registration (e.g. default User.Read) are not used by AzureHound
try {
    $appReg = Get-MgApplication -Filter "appId eq '$($sp.AppId)'" -ErrorAction Stop
    if ($appReg -and $msgraph) {
        $graphRra = $appReg.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $GraphAppId }
        $delegated = foreach ($ra in $graphRra.ResourceAccess) {
            if ($ra.Type -eq "Scope") {
                ($msgraph.Oauth2PermissionScopes | Where-Object { $_.Id -eq $ra.Id }).Value
            }
        }
        $delegated = @($delegated | Where-Object { $_ })
        if ($delegated.Count -gt 0) {
            Add-Result "INFO" "Graph" ("Delegated: " + ($delegated -join ", ")) "Not used by AzureHound (application permissions only) - can be removed"
        }
    }
} catch { <# App registration may live in another tenant (multi-tenant app) - skip #> }

# ===================================================================
# SECTION 8: ENTRA ID ROLES
# Not required for application-based auth - reported for review only
# ===================================================================

Write-Host "=== ENTRA ID ROLES ===" -ForegroundColor Cyan

$entraRoles = $null
try {
    $entraAssignments = Get-MgRoleManagementDirectoryRoleAssignment `
        -Filter "principalId eq '$($sp.Id)'" -All -ErrorAction Stop

    $roleDefCache = @{}
    $entraRoles = @(foreach ($a in $entraAssignments) {
        if (-not $roleDefCache.ContainsKey($a.RoleDefinitionId)) {
            $roleDefCache[$a.RoleDefinitionId] = Get-MgRoleManagementDirectoryRoleDefinition `
                -UnifiedRoleDefinitionId $a.RoleDefinitionId -ErrorAction Stop
        }
        [PSCustomObject]@{
            Role   = $roleDefCache[$a.RoleDefinitionId].DisplayName
            RoleId = $a.RoleDefinitionId
            Scope  = $a.DirectoryScopeId
        }
    })

    if ($entraRoles.Count -gt 0) {
        $entraRoles | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
    } else {
        Write-Host "  No active Entra ID roles assigned (expected - none are required)." -ForegroundColor Green
        Write-Host ""
    }
}
catch {
    Write-Host "  [ERROR] Could not query Entra ID roles: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    if ($_.Exception.Message -like "*not recognized*") {
        Write-Host "  [TIP] Identity.Governance submodule may be missing:" -ForegroundColor DarkGray
        Write-Host "        Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser -Force" -ForegroundColor White
        Write-Host ""
    }
}

if ($null -ne $entraRoles) {
    foreach ($er in $entraRoles) {
        if ($er.Role -eq "Directory Readers") {
            Add-Result "INFO" "Entra" "Directory Readers" "No longer required with application permissions - can be removed if only assigned for AzureHound"
        } else {
            Add-Result "WARN" "Entra" $er.Role "AzureHound needs no Entra ID roles - review whether this is needed"
        }
    }
}

# ===================================================================
# SECTION 9: AZURE RBAC (REST API - no Az module required)
# Requirement: a read-only role (docs: custom 'azurehound-reader-role') assigned at the
# Tenant Root Management Group (ID = tenant ID). Lower scopes silently hide resources.
# ===================================================================

Write-Host "=== AZURE RBAC ROLES ===" -ForegroundColor Cyan

$rbac        = $null
$rootScope   = "/providers/Microsoft.Management/managementGroups/$tenantGuid"
$rootQueryOk = $false

function Invoke-ArmGetAll([string]$Uri) {
    $items = @()
    $next  = $Uri
    while ($next) {
        $resp  = Invoke-RestMethod -Uri $next -Headers @{ Authorization = "Bearer $($script:azToken)" } -ErrorAction Stop
        $items += @($resp.value)
        $next  = $resp.nextLink
    }
    return $items
}

function Test-ActionAllowed($Permissions, [string]$Operation) {
    foreach ($perm in $Permissions) {
        $allowed = $perm.actions    | Where-Object { $Operation -like $_ }
        $denied  = $perm.notActions | Where-Object { $Operation -like $_ }
        if ($allowed -and -not $denied) { return $true }
    }
    return $false
}

if (-not $script:azToken) {
    Write-Host "  [SKIP] No Azure token available - RBAC check skipped" -ForegroundColor Yellow
    Write-Host ""
    Add-Result "UNKNOWN" "Azure RBAC" "Role at Tenant Root Management Group" "Not checked - no Azure token" $true
} else {
    $assignments = @()
    $filter = "`$filter=principalId eq '$($sp.Id)'"

    # 1) Tenant Root Management Group - returns assignments at, above and below the root for this principal
    try {
        $assignments = Invoke-ArmGetAll "https://management.azure.com$rootScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter"
        $rootQueryOk = $true
        Write-Host "  Queried Tenant Root Management Group ($tenantGuid)" -ForegroundColor Gray
    }
    catch {
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        $why = if ($code) { "HTTP $code" } else { $_.Exception.Message }
        Write-Host "  [WARN] Could not read role assignments at the Tenant Root Management Group ($why)." -ForegroundColor Yellow
        Write-Host "         The signed-in user needs read access at the root, or management groups are not enabled." -ForegroundColor DarkGray
        Write-Host "         Falling back to per-subscription checks (cannot confirm root-scope assignment)." -ForegroundColor DarkGray
    }

    # 2) Fallback - per subscription
    if (-not $rootQueryOk) {
        try {
            $subscriptions = Invoke-ArmGetAll "https://management.azure.com/subscriptions?api-version=2020-01-01"
            Write-Host ("  Found {0} subscription(s) visible to the signed-in user" -f @($subscriptions).Count) -ForegroundColor Gray
            foreach ($sub in $subscriptions) {
                try {
                    $assignments += Invoke-ArmGetAll "https://management.azure.com/subscriptions/$($sub.subscriptionId)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter"
                } catch {
                    Write-Host ("  [WARN] Could not query subscription '{0}': {1}" -f $sub.displayName, $_.Exception.Message) -ForegroundColor DarkGray
                }
            }
        } catch {
            Write-Host "  [ERROR] Could not list subscriptions: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""

    # De-duplicate and resolve role definitions
    $assignments = @($assignments | Group-Object -Property id | ForEach-Object { $_.Group[0] })
    $defCache = @{}
    $rbac = @(foreach ($as in $assignments) {
        $defId = $as.properties.roleDefinitionId
        if (-not $defCache.ContainsKey($defId)) {
            try {
                $defCache[$defId] = Invoke-RestMethod -Uri "https://management.azure.com$($defId)?api-version=2022-04-01" `
                    -Headers @{ Authorization = "Bearer $($script:azToken)" } -ErrorAction Stop
            } catch { $defCache[$defId] = $null }
        }
        $def = $defCache[$defId]
        [PSCustomObject]@{
            RoleDefinitionName = if ($def) { $def.properties.roleName } else { $defId.Split('/')[-1] }
            RoleType           = if ($def) { $def.properties.type } else { "Unknown" }
            Scope              = $as.properties.scope
            AtRoot             = ($as.properties.scope -eq $rootScope -or $as.properties.scope -eq "/")
            Permissions        = if ($def) { $def.properties.permissions } else { $null }
        }
    })

    if ($rbac.Count -gt 0) {
        $rbac | Select-Object RoleDefinitionName, RoleType, Scope, AtRoot | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
    } else {
        Write-Host "  No Azure RBAC role assignments found for this service principal." -ForegroundColor Yellow
        Write-Host ""
    }

    # Evaluate
    $privileged = @("Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator")
    foreach ($r in $rbac | Where-Object { $privileged -contains $_.RoleDefinitionName }) {
        Add-Result "WARN" "Azure RBAC" $r.RoleDefinitionName "Write-capable role at $($r.Scope) - AzureHound only needs read access; remove it"
    }

    $rootRoles = @($rbac | Where-Object { $_.AtRoot })
    $rootRead  = $rootRoles | Where-Object { $privileged -notcontains $_.RoleDefinitionName }

    if ($rootRead) {
        foreach ($r in $rootRead) {
            if ($r.RoleType -eq "CustomRole") {
                Add-Result "OK" "Azure RBAC" "$($r.RoleDefinitionName) (custom) at Tenant Root MG" "Recommended setup"
                # Spot-check operations the custom role must allow
                foreach ($op in @("Microsoft.Authorization/roleAssignments/read", "Microsoft.KeyVault/vaults/read")) {
                    if ($r.Permissions -and -not (Test-ActionAllowed $r.Permissions $op)) {
                        Add-Result "WARN" "Azure RBAC" "$($r.RoleDefinitionName): $op" "Custom role does not allow this - compare with the azurehound-reader-role.json from the docs"
                    }
                }
            } elseif ($r.RoleDefinitionName -eq "Reader") {
                Add-Result "OK" "Azure RBAC" "Reader at Tenant Root MG" "Works, but broader than the documented custom 'azurehound-reader-role'"
            } else {
                Add-Result "OK" "Azure RBAC" "$($r.RoleDefinitionName) at Tenant Root MG" "Confirm it grants read across all resource types"
            }
        }
    } elseif ($rootRoles.Count -gt 0) {
        Add-Result "WARN" "Azure RBAC" "Role at Tenant Root MG" "Only write-capable roles assigned at root - replace with the read-only custom role" $true
    } elseif ($rbac.Count -gt 0) {
        $scopes = ($rbac | Select-Object -ExpandProperty Scope -Unique) -join "; "
        if ($rootQueryOk) {
            Add-Result "MISSING" "Azure RBAC" "Role at Tenant Root MG" "Assigned only at lower scope(s): $scopes - resources outside these are silently missed. Assign at the Tenant Root MG." $true
        } else {
            Add-Result "UNKNOWN" "Azure RBAC" "Role at Tenant Root MG" "Found lower-scope assignments ($scopes) but could not read the root MG to confirm" $true
        }
    } else {
        if ($rootQueryOk) {
            Add-Result "MISSING" "Azure RBAC" "Role at Tenant Root MG" "No role assignments found - assign the custom AzureHound reader role at the Tenant Root MG" $true
        } else {
            Add-Result "UNKNOWN" "Azure RBAC" "Role at Tenant Root MG" "None found in visible subscriptions and the root MG could not be read" $true
        }
    }
}

# ===================================================================
# SECTION 10: PERMISSION SUMMARY
# ===================================================================

Write-Host "====================================================================" -ForegroundColor Green
Write-Host "  PERMISSION SUMMARY" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host ""

$statusColour = @{ OK = "Green"; WARN = "Yellow"; MISSING = "Red"; UNKNOWN = "Yellow"; INFO = "Cyan" }

foreach ($area in @("Graph", "Entra", "Azure RBAC")) {
    $areaResults = $results | Where-Object { $_.Area -eq $area }
    if (-not $areaResults) {
        if ($area -eq "Entra") {
            Write-Host "  [OK]      Entra: no roles assigned (none required)" -ForegroundColor Green
        }
        continue
    }
    foreach ($res in $areaResults) {
        $line = "  {0,-9} {1}: {2}" -f "[$($res.Status)]", $area, $res.Item
        if ($res.Note) { $line += " - $($res.Note)" }
        Write-Host $line -ForegroundColor $statusColour[$res.Status]
    }
}

Write-Host ""

$blocking = @($results | Where-Object { $_.Blocking })
$warnings = @($results | Where-Object { $_.Status -eq "WARN" -and -not $_.Blocking })

if ($blocking.Count -eq 0) {
    Write-Host "  RESULT: All required permissions are in place." -ForegroundColor Green
    if ($warnings.Count -gt 0) {
        Write-Host "          $($warnings.Count) recommendation(s) marked [WARN] above." -ForegroundColor Yellow
    }
} else {
    Write-Host "  RESULT: $($blocking.Count) required item(s) are MISSING or UNKNOWN - see above." -ForegroundColor Red
}

Write-Host ""
Write-Host "  Reference: https://bloodhound.specterops.io/collect-data/azurehound-data-permissions" -ForegroundColor DarkGray
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""
