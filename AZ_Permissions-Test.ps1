# ===================================================================
# AzureHound Permission Validator v1.4
# Checks all required permissions for AzureHound Enterprise data collection
# https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration
# ===================================================================

param(
    [string]$AppName  = "AzureHound",
    [string]$TenantId = "",
    [switch]$Skip,      # Skip Connect-MgGraph / Connect-AzAccount if already authenticated
    [switch]$Install    # Auto-install any missing required modules
)

# ===================================================================
# WAM BROKER FIX - MUST BE FIRST - before ANY Az module is touched
# Prevents: "Method not found: SharedTokenCacheCredentialBrokerOptions..ctor"
# Setting the env var is safe even if Az is not installed
# ===================================================================

$env:AZURE_USE_DEVICE_CODE       = "true"
$env:AZURE_CLIENTS_USE_BROKER    = "false"

# Update-AzConfig itself can trigger the WAM error if Az is loaded,
# so we wrap it and silently continue if it fails
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
Write-Host "  AzureHound Permission Validator v1.4" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

# ===================================================================
# SECTION 1: EXECUTION POLICY CHECK
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
    Write-Host "    PowerShell.exe -ExecutionPolicy Bypass -File .\AZ_Permissions-Test.ps1" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "  [OK] Execution policy allows script execution" -ForegroundColor Green
    Write-Host ""
}

# ===================================================================
# SECTION 2: PREREQUISITE MODULE CHECK
# ===================================================================

Write-Host "--- PREREQUISITE MODULE CHECK ---" -ForegroundColor White
Write-Host ""

$prereqsPassed  = $true
$missingModules = @()

$requiredModules = @(
    @{ Name = "Microsoft.Graph";                     MinVersion = "2.0.0" },
    @{ Name = "Microsoft.Graph.Authentication";      MinVersion = "2.0.0" },
    @{ Name = "Microsoft.Graph.Applications";        MinVersion = "2.0.0" },
    @{ Name = "Microsoft.Graph.Identity.Governance"; MinVersion = "2.0.0" }
    # Note: Az.Accounts is NOT required - RBAC uses REST API directly to avoid WAM broker issues
)

foreach ($mod in $requiredModules) {
    $installed = Get-Module -Name $mod.Name -ListAvailable |
                 Sort-Object Version -Descending |
                 Select-Object -First 1

    if ($installed) {
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
        Write-Host "  [-Install] Installing missing/outdated modules now..." -ForegroundColor Yellow
        Write-Host ""
        foreach ($mod in $missingModules) {
            Write-Host "  Installing $($mod.Name)..." -ForegroundColor Cyan
            try {
                Install-Module -Name $mod.Name -Scope CurrentUser -MinimumVersion $mod.MinVersion `
                    -Force -AllowClobber -ErrorAction Stop
                Write-Host "  [OK] $($mod.Name) installed" -ForegroundColor Green
            }
            catch {
                Write-Host "  [FAIL] $($mod.Name) - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Write-Host ""
        Write-Host "  Installation complete." -ForegroundColor Green
        Write-Host "  Please RESTART PowerShell and re-run the script to load the new modules." -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    else {
        Write-Host "  FIX OPTION 1 - Install everything at once (RECOMMENDED):" -ForegroundColor Cyan
        Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor White
        Write-Host "    Install-Module Az -Scope CurrentUser -Force" -ForegroundColor White
        Write-Host ""
        Write-Host "  FIX OPTION 2 - Install only what is missing:" -ForegroundColor Cyan
        foreach ($mod in $missingModules) {
            Write-Host ("    Install-Module {0} -Scope CurrentUser -Force" -f $mod.Name) -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  FIX OPTION 3 - Let this script install everything for you:" -ForegroundColor Cyan
        Write-Host "    .\AZ_Permissions-Test.ps1 -Install" -ForegroundColor White
        Write-Host ""
        Write-Host "  After installing, RESTART PowerShell and re-run." -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }
}

Write-Host "  [OK] All required modules are present" -ForegroundColor Green
Write-Host ""

# ===================================================================
# SECTION 3: WAM BROKER COMPATIBILITY CHECK (informational only)
# RBAC now uses REST API directly so this no longer blocks the script
# ===================================================================

Write-Host "--- WAM BROKER COMPATIBILITY CHECK ---" -ForegroundColor White
Write-Host ""

$azAccounts = Get-Module Az.Accounts          -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
$idBroker   = Get-Module Azure.Identity.Broker -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if ($azAccounts) {
    Write-Host ("  Az.Accounts:           v{0}" -f $azAccounts.Version) -ForegroundColor Gray
} else {
    Write-Host "  Az.Accounts:           Not installed (not required - RBAC uses REST API)" -ForegroundColor Gray
}

if ($idBroker) {
    Write-Host ("  Azure.Identity.Broker: v{0}" -f $idBroker.Version) -ForegroundColor Gray
    Write-Host ""

    if ($azAccounts -and $azAccounts.Version -lt [version]"3.0.0") {
        Write-Host "  [INFO] WAM broker conflict exists but will NOT affect this script" -ForegroundColor Cyan
        Write-Host "         RBAC checks use the Azure REST API directly - Az module not used" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Permanent fix (optional): Update-Module Az.Accounts -Force" -ForegroundColor DarkGray
        Write-Host ""
    } else {
        Write-Host "  [OK] No known WAM broker version conflicts" -ForegroundColor Green
        Write-Host ""
    }
} else {
    Write-Host "  Azure.Identity.Broker: Not installed" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [OK] WAM broker conflict not applicable" -ForegroundColor Green
    Write-Host ""
}

# ===================================================================
# SECTION 4: IMPORT SUBMODULES
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
# SECTION 5: AUTHENTICATION
# ===================================================================

Write-Host "--- AUTHENTICATION ---" -ForegroundColor White
Write-Host ""

if ($Skip) {
    Write-Host "  [SKIP] Bypassing authentication - using existing session" -ForegroundColor Yellow
    Write-Host "         Assumes Connect-MgGraph and Connect-AzAccount already completed" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Verifying existing sessions..." -ForegroundColor Cyan
    Write-Host ""

    # Verify Graph session
    try {
        $mgContext = Get-MgContext -ErrorAction Stop
        if ($mgContext) {
            Write-Host "  [OK] Microsoft Graph - Account: $($mgContext.Account)" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] No active Graph session found" -ForegroundColor Yellow
            Write-Host "         Run: Connect-MgGraph -Scopes 'Application.Read.All','RoleManagement.Read.Directory','Directory.Read.All'" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "  [WARN] Could not verify Graph session: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "         Run: Connect-MgGraph -Scopes 'Application.Read.All','RoleManagement.Read.Directory','Directory.Read.All'" -ForegroundColor DarkGray
    }

    # ---------------------------------------------------------------
    # Azure token - try 3 sources in order:
    #   1. Az PowerShell (Get-AzAccessToken) - if Connect-AzAccount was used
    #   2. Azure CLI     (az account get-access-token) - if az login was used
    #   3. Neither available - RBAC skipped with clear message
    # ---------------------------------------------------------------
    $script:azToken    = $null
    $script:azTenantId = $TenantId

    Write-Host "  Checking for existing Azure token..." -ForegroundColor Cyan

    # Source 1: Az PowerShell module
    try {
        $azContext = Get-AzContext -ErrorAction Stop
        if ($azContext -and $azContext.Account) {
            $script:azTenantId = $azContext.Tenant.Id
            $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
            $script:azToken = $tokenObj.Token
            Write-Host "  [OK] Azure token from Az PowerShell - Account: $($azContext.Account)" -ForegroundColor Green
        }
    }
    catch {
        # WAM broker or no session - try next source
    }

    # Source 2: Azure CLI (az login)
    if (-not $script:azToken) {
        try {
            $azCliCheck = Get-Command az -ErrorAction Stop
            $azCliToken = az account get-access-token --resource "https://management.azure.com/" 2>$null | ConvertFrom-Json -ErrorAction Stop

            if ($azCliToken -and $azCliToken.accessToken) {
                $script:azToken = $azCliToken.accessToken
                if (-not $script:azTenantId) { $script:azTenantId = $azCliToken.tenant }
                Write-Host "  [OK] Azure token from Azure CLI (az login) - Account: $($azCliToken.userId)" -ForegroundColor Green
            }
        }
        catch {
            # Azure CLI not installed or not logged in - try nothing left
        }
    }

    # Source 3: Neither worked
    if (-not $script:azToken) {
        Write-Host "  [WARN] No active Azure session found" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  RBAC check will be skipped. To fix, run ONE of these then retry with -Skip:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Option A - Azure PowerShell:" -ForegroundColor Cyan
        Write-Host "    Connect-AzAccount -DeviceCode" -ForegroundColor White
        Write-Host ""
        Write-Host "  Option B - Azure CLI:" -ForegroundColor Cyan
        Write-Host "    az login" -ForegroundColor White
        Write-Host ""
        Write-Host "  Option C - Provide Tenant ID and re-authenticate:" -ForegroundColor Cyan
        Write-Host "    .\AZ_Permissions-Test.ps1 -TenantId 'your-tenant-id-here'" -ForegroundColor White
    }

    Write-Host ""
}
else {
    # Connect to Microsoft Graph
    Write-Host "  Connecting to Microsoft Graph (browser prompt will open)..." -ForegroundColor Cyan
    try {
        Connect-MgGraph -NoWelcome -Scopes "Application.Read.All","RoleManagement.Read.Directory","Directory.Read.All" -ErrorAction Stop
        Write-Host "  [OK] Microsoft Graph connected" -ForegroundColor Green
    }
    catch {
        Write-Host "  [FAIL] Microsoft Graph connection failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    Write-Host ""

    # ---------------------------------------------------------------
    # Azure auth via REST device code - bypasses Az module / WAM broker entirely
    # ---------------------------------------------------------------
    Write-Host "  Connecting to Azure Management API (device code)..." -ForegroundColor Cyan
    Write-Host "  NOTE: Using REST API directly - no Az module required (avoids WAM broker)" -ForegroundColor DarkGray
    Write-Host ""

    $script:azToken    = $null
    $script:azTenantId = $TenantId

    # If no TenantId supplied, get it from the MgGraph context or Azure CLI
    if (-not $script:azTenantId) {
        try {
            $mgCtx = Get-MgContext -ErrorAction Stop
            $script:azTenantId = $mgCtx.TenantId
        } catch { }
    }

    # Fall back to Azure CLI for tenant ID
    if (-not $script:azTenantId) {
        try {
            $azCliAccount = az account show 2>$null | ConvertFrom-Json -ErrorAction Stop
            $script:azTenantId = $azCliAccount.tenantId
        } catch { }
    }

    if (-not $script:azTenantId) {
        Write-Host "  [WARN] Could not determine Tenant ID - RBAC check will be skipped" -ForegroundColor Yellow
        Write-Host "         Re-run with: .\AZ_Permissions-Test.ps1 -TenantId 'your-tenant-id'" -ForegroundColor DarkGray
    } else {
        try {
            # Step 1: Request device code
            $deviceCodeResponse = Invoke-RestMethod `
                -Method  POST `
                -Uri     "https://login.microsoftonline.com/$($script:azTenantId)/oauth2/v2.0/devicecode" `
                -Body    @{
                    client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI public client ID
                    scope     = "https://management.azure.com/.default offline_access"
                } -ErrorAction Stop

            Write-Host "  $($deviceCodeResponse.message)" -ForegroundColor Yellow
            Write-Host ""

            # Step 2: Poll for token
            $tokenBody = @{
                grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                client_id   = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                device_code = $deviceCodeResponse.device_code
            }

            $expiry    = (Get-Date).AddSeconds($deviceCodeResponse.expires_in)
            $interval  = $deviceCodeResponse.interval
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
                    $errDetail = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($errDetail.error -eq "authorization_pending") { continue }
                    elseif ($errDetail.error -eq "expired_token")     { break }
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
    }

    Write-Host ""
}

# ===================================================================
# SECTION 6: LOCATE SERVICE PRINCIPAL
# ===================================================================

Write-Host "--- LOCATING SERVICE PRINCIPAL: '$AppName' ---" -ForegroundColor White
Write-Host ""

$sp = Get-MgServicePrincipal -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue

if (-not $sp) {
    Write-Host "  [ERROR] Service principal '$AppName' not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Possible fixes:" -ForegroundColor Yellow
    Write-Host "    1. Check the name in Azure Portal > Enterprise Applications" -ForegroundColor Gray
    Write-Host "    2. Re-run with the correct name:" -ForegroundColor Gray
    Write-Host "         .\AZ_Permissions-Test.ps1 -AppName 'YourActualAppName'" -ForegroundColor White
    Write-Host "    3. List all service principals to find the correct name:" -ForegroundColor Gray
    Write-Host "         Get-MgServicePrincipal -Filter ""startswith(displayName,'Azure')"" | Select DisplayName" -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host "  App Name:  $($sp.DisplayName)" -ForegroundColor White
Write-Host "  Object ID: $($sp.Id)"           -ForegroundColor Gray
Write-Host "  App ID:    $($sp.AppId)"        -ForegroundColor Gray
Write-Host ""

# ===================================================================
# SECTION 7: GRAPH API PERMISSIONS
# ===================================================================

Write-Host "=== GRAPH API PERMISSIONS ===" -ForegroundColor Cyan

$graphPerms = $null
try {
    $msgraph            = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -ErrorAction Stop
    $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction Stop

    $graphPerms = foreach ($a in $appRoleAssignments) {
        $role = $msgraph.AppRoles | Where-Object { $_.Id -eq $a.AppRoleId }
        [PSCustomObject]@{
            Permission = $role.Value
            Type       = "Application"
            Consented  = $true
        }
    }

    if ($graphPerms) {
        $graphPerms | Format-Table -AutoSize
    } else {
        Write-Host "  No Graph API permissions found." -ForegroundColor Yellow
        Write-Host ""
    }
}
catch {
    Write-Host "  [ERROR] Could not query Graph permissions: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# ===================================================================
# SECTION 8: ENTRA ID ROLES
# ===================================================================

Write-Host "=== ENTRA ID ROLES ===" -ForegroundColor Cyan

$entraRoles = $null
try {
    $entraAssignments = Get-MgRoleManagementDirectoryRoleAssignment `
        -Filter "principalId eq '$($sp.Id)'" -ErrorAction Stop

    $entraRoles = foreach ($a in $entraAssignments) {
        $roleDef = Get-MgRoleManagementDirectoryRoleDefinition `
            -UnifiedRoleDefinitionId $a.RoleDefinitionId -ErrorAction Stop
        [PSCustomObject]@{
            Role   = $roleDef.DisplayName
            RoleId = $a.RoleDefinitionId
            Status = "Active"
        }
    }

    if ($entraRoles) {
        $entraRoles | Format-Table -AutoSize
    } else {
        Write-Host "  No Entra ID roles found." -ForegroundColor Yellow
        Write-Host ""
    }
}
catch {
    Write-Host "  [ERROR] Could not query Entra ID roles: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    if ($_.Exception.Message -like "*not recognized*" -or $_.Exception.Message -like "*not found*") {
        Write-Host "  [TIP] Identity.Governance submodule may be missing:" -ForegroundColor DarkGray
        Write-Host "        Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser -Force" -ForegroundColor White
        Write-Host ""
    }
}

# ===================================================================
# SECTION 9: AZURE RBAC ROLES (REST API - no Az module required)
# ===================================================================

Write-Host "=== AZURE RBAC ROLES ===" -ForegroundColor Cyan

$rbac = $null

if (-not $script:azToken) {
    Write-Host "  [SKIP] No Azure token available - RBAC check skipped" -ForegroundColor Yellow
    Write-Host "         Re-run without -Skip to authenticate, or provide -TenantId" -ForegroundColor DarkGray
    Write-Host ""
} else {
    try {
        # Get all subscriptions first
        $subsResponse = Invoke-RestMethod `
            -Uri     "https://management.azure.com/subscriptions?api-version=2020-01-01" `
            -Headers @{ Authorization = "Bearer $($script:azToken)" } `
            -ErrorAction Stop

        $subscriptions = $subsResponse.value
        Write-Host ("  Found {0} subscription(s)" -f $subscriptions.Count) -ForegroundColor Gray

        $allRoles = @()

        foreach ($sub in $subscriptions) {
            $subId  = $sub.subscriptionId
            $subName = $sub.displayName

            # Get role assignments for the service principal in this subscription
            $roleUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$($sp.Id)'"

            try {
                $roleResponse = Invoke-RestMethod `
                    -Uri     $roleUri `
                    -Headers @{ Authorization = "Bearer $($script:azToken)" } `
                    -ErrorAction Stop

                foreach ($assignment in $roleResponse.value) {
                    # Resolve role definition name
                    $roleDefId   = $assignment.properties.roleDefinitionId
                    $roleDefName = $roleDefId.Split('/')[-1]

                    try {
                        $roleDefUri = "https://management.azure.com$($roleDefId)?api-version=2022-04-01"
                        $roleDef    = Invoke-RestMethod `
                            -Uri     $roleDefUri `
                            -Headers @{ Authorization = "Bearer $($script:azToken)" } `
                            -ErrorAction Stop
                        $roleDefName = $roleDef.properties.roleName
                    } catch { }

                    $allRoles += [PSCustomObject]@{
                        RoleDefinitionName = $roleDefName
                        Scope              = $assignment.properties.scope
                        Subscription       = $subName
                    }
                }
            } catch {
                Write-Host ("  [WARN] Could not query subscription '{0}': {1}" -f $subName, $_.Exception.Message) -ForegroundColor DarkGray
            }
        }

        $rbac = $allRoles

        if ($rbac -and $rbac.Count -gt 0) {
            $rbac | Format-Table -AutoSize
        } else {
            Write-Host "  No Azure RBAC roles found for this service principal." -ForegroundColor Yellow
            Write-Host ""
        }
    }
    catch {
        Write-Host "  [ERROR] Could not query Azure RBAC via REST API: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
    }
}

# ===================================================================
# SECTION 10: PERMISSION SUMMARY
# ===================================================================

Write-Host "====================================================================" -ForegroundColor Green
Write-Host "  PERMISSION SUMMARY" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host ""

$allRequired = $true

# Required Graph permissions
foreach ($p in @("Directory.Read.All", "RoleManagement.Read.All")) {
    if ($graphPerms | Where-Object { $_.Permission -eq $p }) {
        Write-Host ("  [OK]      Graph: {0}" -f $p) -ForegroundColor Green
    } else {
        Write-Host ("  [MISSING] Graph: {0}" -f $p) -ForegroundColor Red
        $allRequired = $false
    }
}

# Optional Graph permissions
foreach ($p in @("AuditLog.Read.All")) {
    if ($graphPerms | Where-Object { $_.Permission -eq $p }) {
        Write-Host ("  [OK]      Graph: {0} (optional)" -f $p) -ForegroundColor Green
    } else {
        Write-Host ("  [NOT SET] Graph: {0} (optional)" -f $p) -ForegroundColor Yellow
    }
}

# Entra ID role
if ($null -eq $entraRoles) {
    Write-Host "  [UNKNOWN] Entra Role: Directory Readers (query failed - see errors above)" -ForegroundColor Yellow
    $allRequired = $false
} elseif ($entraRoles | Where-Object { $_.Role -eq "Directory Readers" }) {
    Write-Host "  [OK]      Entra Role: Directory Readers" -ForegroundColor Green
} else {
    Write-Host "  [MISSING] Entra Role: Directory Readers" -ForegroundColor Red
    $allRequired = $false
}

# Azure RBAC
if ($null -eq $rbac) {
    Write-Host "  [UNKNOWN] Azure RBAC: Reader (query failed - see errors above)" -ForegroundColor Yellow
} elseif ($rbac | Where-Object { $_.RoleDefinitionName -eq "Reader" }) {
    Write-Host "  [OK]      Azure RBAC: Reader" -ForegroundColor Green
} else {
    Write-Host "  [MISSING] Azure RBAC: Reader" -ForegroundColor Red
    $allRequired = $false
}

Write-Host ""

if ($allRequired) {
    Write-Host "  RESULT: All required permissions are configured correctly!" -ForegroundColor Green
} else {
    Write-Host "  RESULT: One or more required permissions are MISSING or UNKNOWN" -ForegroundColor Red
    Write-Host "          Review items marked [MISSING] or [UNKNOWN] above" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""
