# AzureHound Permission Validator
# Checks all required permissions for AzureHound Enterprise data collection
# https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration

param(
    [string]$AppName = "AzureHound",
    [string]$TenantId = ""
)

# Connect to Microsoft Graph
Connect-MgGraph -NoWelcome -Scopes "Application.Read.All","RoleManagement.Read.Directory","Directory.Read.All"

# Connect to Azure (bypass WAM broker issues)
if ($TenantId) {
    $env:AZURE_USE_DEVICE_CODE = "true"
    Update-AzConfig -EnableLoginByWam $false -Scope Process
    Connect-AzAccount -DeviceCode -TenantId $TenantId
} else {
    try {
        $env:AZURE_USE_DEVICE_CODE = "true"
        Update-AzConfig -EnableLoginByWam $false -Scope Process
        Connect-AzAccount -DeviceCode
    } catch {
        Write-Host "  Azure connection failed. RBAC check will be skipped." -ForegroundColor Yellow
    }
}

# Get the service principal
$sp = Get-MgServicePrincipal -Filter "displayName eq '$AppName'"

if (-not $sp) {
    Write-Host "ERROR: Service principal '$AppName' not found!" -ForegroundColor Red
    Write-Host "Make sure you have an App Registration with an associated Enterprise Application." -ForegroundColor Red
    return
}

Write-Host "`n====================================" -ForegroundColor White
Write-Host " AzureHound Permission Validator" -ForegroundColor White
Write-Host "====================================" -ForegroundColor White
Write-Host "App Name:    $($sp.DisplayName)"
Write-Host "Object ID:   $($sp.Id)"
Write-Host "App ID:      $($sp.AppId)"

# 1. Graph API Permissions
Write-Host "`n=== GRAPH API PERMISSIONS ===" -ForegroundColor Cyan
$msgraph = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
$appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
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
}

# 2. Entra ID Directory Roles (via unified RBAC API - catches PIM assignments)
Write-Host "=== ENTRA ID ROLES ===" -ForegroundColor Cyan
$entraAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($sp.Id)'"
$entraRoles = foreach ($a in $entraAssignments) {
    $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId
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
}

# 3. Azure RBAC Roles
Write-Host "=== AZURE RBAC ROLES ===" -ForegroundColor Cyan
try {
    $rbac = Get-AzRoleAssignment -ObjectId $sp.Id -ErrorAction Stop |
        Select-Object RoleDefinitionName, Scope
    if ($rbac) {
        $rbac | Format-Table -AutoSize
    } else {
        Write-Host "  No Azure RBAC roles found." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Could not query Azure RBAC: $($_.Exception.Message)" -ForegroundColor Red
    $rbac = $null
}

# Summary
Write-Host "====================================" -ForegroundColor Green
Write-Host " PERMISSION SUMMARY" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green

$required = @("Directory.Read.All", "RoleManagement.Read.All")
$optional = @("AuditLog.Read.All")

foreach ($p in $required) {
    $found = $graphPerms | Where-Object { $_.Permission -eq $p }
    $status = if ($found) { "[OK]" } else { "[MISSING]" }
    $color = if ($found) { "Green" } else { "Red" }
    Write-Host "  Graph: $p $status" -ForegroundColor $color
}
foreach ($p in $optional) {
    $found = $graphPerms | Where-Object { $_.Permission -eq $p }
    $status = if ($found) { "[OK]" } else { "[NOT SET]" }
    $color = if ($found) { "Green" } else { "Yellow" }
    Write-Host "  Graph: $p (optional) $status" -ForegroundColor $color
}

$dirReader = $entraRoles | Where-Object { $_.Role -eq "Directory Readers" }
$status = if ($dirReader) { "[OK]" } else { "[MISSING]" }
$color = if ($dirReader) { "Green" } else { "Red" }
Write-Host "  Entra Role: Directory Readers $status" -ForegroundColor $color

if ($rbac) {
    $readerRole = $rbac | Where-Object { $_.RoleDefinitionName -eq "Reader" }
    $status = if ($readerRole) { "[OK]" } else { "[MISSING]" }
    $color = if ($readerRole) { "Green" } else { "Red" }
    Write-Host "  Azure RBAC: Reader $status" -ForegroundColor $color
} else {
    Write-Host "  Azure RBAC: Reader [UNKNOWN - Az connection failed]" -ForegroundColor Yellow
}
