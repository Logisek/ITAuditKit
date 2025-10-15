#Requires -Version 7.0

<#
.SYNOPSIS
    Retrieves user login timestamps from local computer, Active Directory, and/or Entra ID.

.DESCRIPTION
    This script retrieves user login information from local computer Windows Event Log,
    Active Directory, and/or Entra ID (Azure AD) sign-in logs. It displays the last X 
    login timestamps in human-readable format using the current computer's timezone.

.PARAMETER UserName
    The username to query login history for. If not specified, queries all users.

.PARAMETER MaxRecords
    The maximum number of login records to retrieve. Default is 10.

.PARAMETER ComputerName
    The computer to query. Default is the local computer.

.PARAMETER IncludeLocal
    Include local computer login logs from Windows Event Log.

.PARAMETER IncludeEntraID
    Include Entra ID (Azure AD) login logs. Requires Microsoft.Graph PowerShell module.

.PARAMETER IncludeAD
    Include Active Directory login logs. Requires ActiveDirectory PowerShell module.

.PARAMETER ListUsers
    List all users from the selected sources with their most recent login information.

.EXAMPLE
    .\users.ps1
    Displays the help menu (default behavior when no arguments provided)

.EXAMPLE
    .\users.ps1 -IncludeLocal -MaxRecords 20
    Retrieves the last 20 login timestamps for all users from local computer

.EXAMPLE
    .\users.ps1 -IncludeEntraID -UserName "jdoe@contoso.com" -MaxRecords 5
    Retrieves the last 5 Entra ID login timestamps for user "jdoe@contoso.com"

.EXAMPLE
    .\users.ps1 -IncludeAD -UserName "jdoe" -MaxRecords 5
    Retrieves the last 5 Active Directory login timestamps for user "jdoe"

.EXAMPLE
    .\users.ps1 -IncludeLocal -IncludeAD -IncludeEntraID -MaxRecords 10
    Retrieves login timestamps from local computer, Active Directory, and Entra ID

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers
    Lists all users from Entra ID with their most recent login information

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers -MaxRecords 50
    Lists first 50 users from Entra ID with their most recent login information

.EXAMPLE
    .\users.ps1 -IncludeAD -ListUsers
    Lists all Active Directory users with their most recent login information

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers -Verbose
    Lists Entra ID users with verbose output showing detailed processing information

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers -FilterByDepartment "IT" -ShowOnlyNoMFA
    Lists IT department users who don't have MFA enabled

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers -FilterByRiskLevel "Critical" -ShowOnlyPrivileged
    Lists critical risk privileged accounts

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers -InactiveDays 90
    Lists all users who haven't logged in for 90+ days

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers -UseCache -CacheExpiryMinutes 30
    Uses cached data if available and less than 30 minutes old

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "SOX","HIPAA"
    Generates SOX and HIPAA compliance reports

.EXAMPLE
    .\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "All"
    Generates compliance reports for all frameworks (SOX, HIPAA, GDPR, PCI-DSS, ISO27001, NIST, CIS)

.NOTES
    Author: IT Audit Kit
    Version: 4.0
    
    IMPORTANT: This script requires PowerShell 7.0 or higher!
    
    Requires: 
        - PowerShell 7.0+ (Install: winget install Microsoft.PowerShell)
        - Administrator privileges to read local Security event log
        - ActiveDirectory PowerShell module for AD logs
        - Microsoft.Graph PowerShell modules for Entra ID logs (Users, Reports, Authentication)
        - UserAuthenticationMethod.Read.All and Device.Read.All permissions for Entra ID
    
    To run with PowerShell 7:
        pwsh -File .\users.ps1 -Profile Quick
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Username to query")]
    [string]$UserName,
    
    [Parameter(Mandatory=$false, HelpMessage="Maximum number of records to retrieve")]
    [ValidateRange(1,1000)]
    [int]$MaxRecords = 10,
    
    [Parameter(Mandatory=$false, HelpMessage="Computer name to query")]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false, HelpMessage="Include local computer login logs")]
    [switch]$IncludeLocal,
    
    [Parameter(Mandatory=$false, HelpMessage="Include Active Directory login logs")]
    [switch]$IncludeAD,
    
    [Parameter(Mandatory=$false, HelpMessage="Include Entra ID login logs")]
    [switch]$IncludeEntraID,
    
    [Parameter(Mandatory=$false, HelpMessage="List all users with most recent login info")]
    [switch]$ListUsers,
    
    [Parameter(Mandatory=$false, HelpMessage="When listing users, include Windows Hello (PIN) registration and last WHfB sign-in")]
    [switch]$IncludePIN,
    
    [Parameter(Mandatory=$false, HelpMessage="Show minimal information when listing users (User, User Rights, MFA Enforcement, Roles, Last Login)")]
    [switch]$Minimal,
    
    [Parameter(Mandatory=$false, HelpMessage="Show results in Out-GridView window (GUI table)")]
    [switch]$OutGridView,
    
    [Parameter(Mandatory=$false, HelpMessage="Export results to an Excel file (requires ImportExcel module)")]
    [switch]$ExportExcel,
    
    [Parameter(Mandatory=$false, HelpMessage="Path to Excel file for export (default: Users_List.xlsx or Login_Records.xlsx)")]
    [string]$ExcelPath,
    
    [Parameter(Mandatory=$false, HelpMessage="Worksheet name for Excel export (default: Users or Logins)")]
    [string]$ExcelWorksheet,
    
    [Parameter(Mandatory=$false, HelpMessage="Output directory for all exported files (default: current directory)")]
    [string]$OutputDirectory = ".",
    
    [Parameter(Mandatory=$false, HelpMessage="Include security risk scoring for users")]
    [switch]$IncludeRiskScore,
    
    [Parameter(Mandatory=$false, HelpMessage="Identify and flag privileged accounts with risk indicators")]
    [switch]$IncludePrivilegedAccounts,
    
    [Parameter(Mandatory=$false, HelpMessage="Detect and analyze service accounts (non-interactive, application accounts)")]
    [switch]$IncludeServiceAccounts,
    
    [Parameter(Mandatory=$false, HelpMessage="Identify and analyze guest users with access expiration dates")]
    [switch]$IncludeGuestUsers,
    
    [Parameter(Mandatory=$false, HelpMessage="Check password policy compliance (age, complexity, history)")]
    [switch]$IncludePasswordPolicy,
    
    [Parameter(Mandatory=$false, HelpMessage="Analyze account lockout events and failed login attempts")]
    [switch]$IncludeAccountLockout,
    
    [Parameter(Mandatory=$false, HelpMessage="Add device compliance status for Entra ID (managed, compliant, etc.)")]
    [switch]$IncludeDeviceCompliance,
    
    [Parameter(Mandatory=$false, HelpMessage="Add Conditional Access policy analysis for Entra ID users")]
    [switch]$IncludeConditionalAccess,
    
    [Parameter(Mandatory=$false, HelpMessage="Integrate Microsoft Graph Identity Protection risky sign-ins")]
    [switch]$IncludeRiskySignins,
    
    [Parameter(Mandatory=$false, HelpMessage="Analyze group memberships and nested group relationships")]
    [switch]$IncludeGroupMembership,
    
    [Parameter(Mandatory=$false, HelpMessage="Audit application permissions and consent grants")]
    [switch]$IncludeAppPermissions,
    
    [Parameter(Mandatory=$false, HelpMessage="Add multiple export formats (CSV, JSON, HTML report)")]
    [switch]$IncludeExportFormats,
    
    [Parameter(Mandatory=$false, HelpMessage="Display help information")]
    [switch]$Help,
    
    [Parameter(Mandatory=$false, HelpMessage="Configuration file path (JSON format)")]
    [string]$ConfigFile,
    
    [Parameter(Mandatory=$false, HelpMessage="Use predefined security audit profile")]
    [ValidateSet("Quick", "Standard", "Comprehensive", "Executive", "Compliance")]
    [string]$Profile,
    
    # Advanced Filtering Parameters
    [Parameter(Mandatory=$false, HelpMessage="Filter users by department")]
    [string]$FilterByDepartment,
    
    [Parameter(Mandatory=$false, HelpMessage="Filter users by office location")]
    [string]$FilterByLocation,
    
    [Parameter(Mandatory=$false, HelpMessage="Filter users by job title")]
    [string]$FilterByJobTitle,
    
    [Parameter(Mandatory=$false, HelpMessage="Filter users who logged in after this date")]
    [datetime]$LastLoginAfter,
    
    [Parameter(Mandatory=$false, HelpMessage="Filter users who logged in before this date")]
    [datetime]$LastLoginBefore,
    
    [Parameter(Mandatory=$false, HelpMessage="Filter by risk level (Critical, High, Medium, Low, Minimal)")]
    [ValidateSet("Critical", "High", "Medium", "Low", "Minimal")]
    [string]$FilterByRiskLevel,
    
    [Parameter(Mandatory=$false, HelpMessage="Show only users without MFA")]
    [switch]$ShowOnlyNoMFA,
    
    [Parameter(Mandatory=$false, HelpMessage="Show only privileged accounts")]
    [switch]$ShowOnlyPrivileged,
    
    [Parameter(Mandatory=$false, HelpMessage="Show only disabled accounts")]
    [switch]$ShowOnlyDisabled,
    
    [Parameter(Mandatory=$false, HelpMessage="Show only guest users")]
    [switch]$ShowOnlyGuests,
    
    [Parameter(Mandatory=$false, HelpMessage="Show only inactive accounts (no login in X days)")]
    [int]$InactiveDays,
    
    # Caching Parameters
    [Parameter(Mandatory=$false, HelpMessage="Use cached data if available")]
    [switch]$UseCache,
    
    [Parameter(Mandatory=$false, HelpMessage="Cache expiry time in minutes (default: 60)")]
    [int]$CacheExpiryMinutes = 60,
    
    [Parameter(Mandatory=$false, HelpMessage="Clear cache before running")]
    [switch]$ClearCache,
    
    # Compliance Reporting Parameters
    [Parameter(Mandatory=$false, HelpMessage="Generate compliance report for specific framework")]
    [ValidateSet("SOX", "HIPAA", "GDPR", "PCI-DSS", "ISO27001", "NIST", "CIS", "All")]
    [string[]]$ComplianceFramework
)

#region PowerShell Version Check
# Check PowerShell version before executing
$psVersion = $PSVersionTable.PSVersion

if ($psVersion.Major -lt 7) {
    Write-Host "`n" + "="*70 -ForegroundColor Red
    Write-Host "UNSUPPORTED POWERSHELL VERSION" -ForegroundColor Red
    Write-Host "="*70 -ForegroundColor Red
    Write-Host ""
    Write-Host "Current Version: PowerShell $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor Yellow
    Write-Host "Required Version: PowerShell 7.0 or higher" -ForegroundColor Green
    Write-Host ""
    Write-Host "This script requires PowerShell 7+ due to:" -ForegroundColor White
    Write-Host "  - Modern parsing features" -ForegroundColor Gray
    Write-Host "  - Improved error handling" -ForegroundColor Gray
    Write-Host "  - Better string processing" -ForegroundColor Gray
    Write-Host "  - Enhanced module support" -ForegroundColor Gray
    Write-Host ""
    Write-Host "HOW TO FIX:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Option 1: Install PowerShell 7 (Recommended)" -ForegroundColor Yellow
    Write-Host "  winget install Microsoft.PowerShell" -ForegroundColor White
    Write-Host ""
    Write-Host "Option 2: Download from GitHub" -ForegroundColor Yellow
    Write-Host "  https://github.com/PowerShell/PowerShell/releases" -ForegroundColor White
    Write-Host ""
    Write-Host "Option 3: Use Chocolatey" -ForegroundColor Yellow
    Write-Host "  choco install powershell-core" -ForegroundColor White
    Write-Host ""
    Write-Host "After installing, run this script with PowerShell 7:" -ForegroundColor Cyan
    Write-Host "  pwsh -File $($MyInvocation.MyCommand.Path) $($MyInvocation.Line -replace '.*\\users\.ps1\s*','')" -ForegroundColor White
    Write-Host ""
    Write-Host "Or launch PowerShell 7 and run:" -ForegroundColor Cyan
    Write-Host "  pwsh" -ForegroundColor White
    Write-Host "  cd $(Split-Path $MyInvocation.MyCommand.Path)" -ForegroundColor White
    Write-Host "  .\users.ps1 $($args -join ' ')" -ForegroundColor White
    Write-Host ""
    Write-Host "="*70 -ForegroundColor Red
    Write-Host ""
    
    # Exit with error code
    exit 1
}

Write-Verbose "PowerShell version check passed: $($psVersion.Major).$($psVersion.Minor).$($psVersion.Build)"
#endregion

#region Output Directory Validation
# Ensure output directory exists and is accessible
if ($OutputDirectory) {
    try {
        # Resolve to absolute path if it exists
        $resolvedPath = Resolve-Path -Path $OutputDirectory -ErrorAction SilentlyContinue
        
        # If path doesn't exist, try to create it
        if (-not $resolvedPath) {
            $OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
            if (-not (Test-Path -Path $OutputDirectory)) {
                Write-Host "Creating output directory: $OutputDirectory" -ForegroundColor Cyan
                New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
                $resolvedPath = Resolve-Path -Path $OutputDirectory
            }
        }
        
        # Convert to string if it's a PathInfo object
        if ($resolvedPath) {
            $OutputDirectory = $resolvedPath.Path
        }
        
        # Test write access
        $testFile = Join-Path $OutputDirectory ".test_write_$(Get-Random).tmp"
        try {
            New-Item -ItemType File -Path $testFile -Force | Out-Null
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
            Write-Verbose "Output directory validated: $OutputDirectory"
        } catch {
            Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "Cannot write to output directory: $OutputDirectory"
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Falling back to current directory." -ForegroundColor Yellow
            $OutputDirectory = "."
        }
        
    } catch {
        Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Invalid output directory: $OutputDirectory"
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Falling back to current directory." -ForegroundColor Yellow
        $OutputDirectory = "."
    }
}

# Ensure OutputDirectory has no trailing slash for consistent path joins
$OutputDirectory = $OutputDirectory.TrimEnd('\', '/')
#endregion

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to show progress with timing
function Show-ProgressWithTiming {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem = ""
    )
    
    if ($Total -gt 0) {
        $percentComplete = [Math]::Min(100, [Math]::Max(0, ($Current / $Total) * 100))
        $statusText = if ($CurrentItem) { "$Status - $CurrentItem" } else { $Status }
        
        Write-Progress -Activity $Activity -Status $statusText -PercentComplete $percentComplete -CurrentOperation "Processing item $Current of $Total"
    }
}

# Function to measure and display execution time
function Measure-ExecutionTime {
    param(
        [scriptblock]$ScriptBlock,
        [string]$OperationName = "Operation"
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $ScriptBlock
        $stopwatch.Stop()
        Write-Host "✓ $OperationName completed in $($stopwatch.Elapsed.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Green
        return $result
    } catch {
        $stopwatch.Stop()
        Write-Host "✗ $OperationName failed after $($stopwatch.Elapsed.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Red
        throw
    }
}

# Function to show operation status
function Write-OperationStatus {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $prefix = switch ($Type) {
        "Info" { "[i]" }
        "Success" { "[+]" }
        "Warning" { "[!]" }
        "Error" { "[x]" }
    }
    
    $color = switch ($Type) {
        "Info" { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
    }
    
    Write-Host "[$timestamp] $prefix $Message" -ForegroundColor $color
}

# Function to generate security audit summary
function Show-SecuritySummary {
    param(
        [array]$UserData,
        [array]$LoginData = @()
    )
    
    if (-not $UserData -or $UserData.Count -eq 0) {
        Write-OperationStatus "No user data available for summary" "Warning"
        return
    }
    
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "SECURITY AUDIT SUMMARY" -ForegroundColor Cyan
    Write-Host "="*60 -ForegroundColor Cyan
    
    # Basic Statistics
    $totalUsers = $UserData.Count
    $enabledUsers = ($UserData | Where-Object { $_.Status -eq "Enabled" -or $_.Enabled -eq $true }).Count
    $disabledUsers = $totalUsers - $enabledUsers
    
    Write-Host "`n[USER OVERVIEW]" -ForegroundColor Yellow
    Write-Host "  Total Users Analyzed: $totalUsers" -ForegroundColor White
    Write-Host "  Enabled Users: $enabledUsers" -ForegroundColor Green
    Write-Host "  Disabled Users: $disabledUsers" -ForegroundColor Red
    
    # MFA Statistics
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $usersWithoutMFA = $totalUsers - $usersWithMFA
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    
    Write-Host "`n[MFA STATUS]" -ForegroundColor Yellow
    Write-Host "  Users with MFA: $usersWithMFA - $mfaPercentage percent" -ForegroundColor Green
    Write-Host "  Users without MFA: $usersWithoutMFA" -ForegroundColor Red
    
    # Risk Analysis
    if ($UserData[0].PSObject.Properties.Name -contains 'RiskLevel') {
        $criticalRisk = ($UserData | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highRisk = ($UserData | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumRisk = ($UserData | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        $lowRisk = ($UserData | Where-Object { $_.RiskLevel -eq "Low" }).Count
        $minimalRisk = ($UserData | Where-Object { $_.RiskLevel -eq "Minimal" }).Count
        
        Write-Host "`n[RISK ANALYSIS]" -ForegroundColor Yellow
        Write-Host "  Critical Risk: $criticalRisk" -ForegroundColor Red
        Write-Host "  High Risk: $highRisk" -ForegroundColor DarkRed
        Write-Host "  Medium Risk: $mediumRisk" -ForegroundColor Yellow
        Write-Host "  Low Risk: $lowRisk" -ForegroundColor Green
        Write-Host "  Minimal Risk: $minimalRisk" -ForegroundColor DarkGreen
    }
    
    # Privileged Accounts
    if ($UserData[0].PSObject.Properties.Name -contains 'IsPrivileged') {
        $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
        $privilegedWithoutMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
        
        Write-Host "`n[PRIVILEGED ACCOUNTS]" -ForegroundColor Yellow
        Write-Host "  Total Privileged: $privilegedUsers" -ForegroundColor White
        Write-Host "  Privileged without MFA: $privilegedWithoutMFA" -ForegroundColor Red
    }
    
    # Service Accounts
    if ($UserData[0].PSObject.Properties.Name -contains 'IsServiceAccount') {
        $serviceAccounts = ($UserData | Where-Object { $_.IsServiceAccount -eq $true }).Count
        $serviceWithoutMFA = ($UserData | Where-Object { $_.IsServiceAccount -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
        
        Write-Host "`n[SERVICE ACCOUNTS]" -ForegroundColor Yellow
        Write-Host "  Total Service Accounts: $serviceAccounts" -ForegroundColor White
        Write-Host "  Service Accounts without MFA: $serviceWithoutMFA" -ForegroundColor Red
    }
    
    # Guest Users
    if ($UserData[0].PSObject.Properties.Name -contains 'IsGuestUser') {
        $guestUsers = ($UserData | Where-Object { $_.IsGuestUser -eq $true }).Count
        $guestWithoutMFA = ($UserData | Where-Object { $_.IsGuestUser -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
        
        Write-Host "`n[GUEST USERS]" -ForegroundColor Yellow
        Write-Host "  Total Guest Users: $guestUsers" -ForegroundColor White
        Write-Host "  Guest Users without MFA: $guestWithoutMFA" -ForegroundColor Red
    }
    
    # Password Policy Compliance
    if ($UserData[0].PSObject.Properties.Name -contains 'PasswordPolicyLevel') {
        $compliantPasswords = ($UserData | Where-Object { $_.PasswordPolicyLevel -eq "Compliant" }).Count
        $nonCompliantPasswords = ($UserData | Where-Object { $null -ne $_.PasswordPolicyLevel -and $_.PasswordPolicyLevel -ne "Compliant" }).Count
        
        Write-Host "`n[PASSWORD COMPLIANCE]" -ForegroundColor Yellow
        Write-Host "  Compliant Passwords: $compliantPasswords" -ForegroundColor Green
        Write-Host "  Non-Compliant Passwords: $nonCompliantPasswords" -ForegroundColor Red
    }
    
    # Login Activity
    if ($LoginData -and $LoginData.Count -gt 0) {
        $recentLogins = ($LoginData | Where-Object { $_.TimeStamp -gt (Get-Date).AddDays(-30) }).Count
        $neverLoggedIn = ($UserData | Where-Object { $_.TimeStamp -eq [DateTime]::MinValue }).Count
        
        Write-Host "`n[LOGIN ACTIVITY] (Last 30 days)" -ForegroundColor Yellow
        Write-Host "  Recent Logins: $recentLogins" -ForegroundColor Green
        Write-Host "  Never Logged In: $neverLoggedIn" -ForegroundColor Red
    }
    
    # Security Recommendations
    Write-Host "`n[SECURITY RECOMMENDATIONS]" -ForegroundColor Yellow
    if ($usersWithoutMFA -gt 0) {
        Write-Host "  • Enable MFA for $usersWithoutMFA users without MFA" -ForegroundColor Red
    }
    if ($privilegedWithoutMFA -gt 0) {
        Write-Host "  • CRITICAL: Enable MFA for $privilegedWithoutMFA privileged accounts" -ForegroundColor Red
    }
    if ($serviceWithoutMFA -gt 0) {
        Write-Host "  • Review MFA requirements for $serviceWithoutMFA service accounts" -ForegroundColor Yellow
    }
    if ($guestWithoutMFA -gt 0) {
        Write-Host "  • Enable MFA for $guestWithoutMFA guest users" -ForegroundColor Yellow
    }
    if ($nonCompliantPasswords -gt 0) {
        Write-Host "  • Address password policy violations for $nonCompliantPasswords users" -ForegroundColor Yellow
    }
    if ($neverLoggedIn -gt 0) {
        Write-Host "  • Review $neverLoggedIn accounts that have never logged in" -ForegroundColor Yellow
    }
    
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
}

# Function to invoke operations with retry logic
function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 2,
        [string]$OperationName = "Operation"
    )
    
    $attempt = 1
    $lastException = $null
    
    while ($attempt -le $MaxRetries) {
        try {
            Write-OperationStatus "Attempting $OperationName (Attempt $attempt of $MaxRetries)" "Info"
            $result = & $ScriptBlock
            Write-OperationStatus "$OperationName completed successfully" "Success"
            return $result
        } catch {
            $lastException = $_
            Write-OperationStatus "$OperationName failed on attempt $attempt`: $($_.Exception.Message)" "Warning"
            
            if ($attempt -lt $MaxRetries) {
                $delay = $DelaySeconds * [Math]::Pow(2, $attempt - 1) # Exponential backoff
                Write-OperationStatus "Retrying in $delay seconds..." "Info"
                Start-Sleep -Seconds $delay
            }
            $attempt++
        }
    }
    
    Write-OperationStatus "$OperationName failed after $MaxRetries attempts" "Error"
    throw $lastException
}

# Function to handle API throttling
function Invoke-WithThrottling {
    param(
        [scriptblock]$ScriptBlock,
        [string]$OperationName = "API Operation"
    )
    
    try {
        return & $ScriptBlock
    } catch {
        if ($_.Exception.Message -like "*throttled*" -or $_.Exception.Message -like "*429*" -or $_.Exception.Message -like "*rate limit*") {
            Write-OperationStatus "API rate limit reached for $OperationName. Waiting 60 seconds..." "Warning"
            Start-Sleep -Seconds 60
            Write-OperationStatus "Retrying $OperationName after rate limit delay" "Info"
            return & $ScriptBlock
        } else {
            throw
        }
    }
}

# Function to validate prerequisites
function Test-Prerequisites {
    param(
        [string[]]$RequiredModules = @(),
        [string[]]$RequiredCommands = @()
    )
    
    $missingItems = @()
    
    # Check required modules
    foreach ($module in $RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingItems += "Module: $module"
        }
    }
    
    # Check required commands
    foreach ($command in $RequiredCommands) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            $missingItems += "Command: $command"
        }
    }
    
    if ($missingItems.Count -gt 0) {
        Write-OperationStatus "Missing prerequisites:" "Error"
        foreach ($item in $missingItems) {
            Write-Host "  • $item" -ForegroundColor Red
        }
        return $false
    }
    
    return $true
}

#region Advanced Filtering Functions
# Function to apply advanced filters to user data
function Invoke-AdvancedFilters {
    param(
        [array]$UserData,
        [string]$Department,
        [string]$Location,
        [string]$JobTitle,
        [AllowNull()]
        [datetime]$LoginAfter,
        [AllowNull()]
        [datetime]$LoginBefore,
        [string]$RiskLevel,
        [switch]$OnlyNoMFA,
        [switch]$OnlyPrivileged,
        [switch]$OnlyDisabled,
        [switch]$OnlyGuests,
        [int]$InactiveDays
    )
    
    Write-OperationStatus "Applying advanced filters..." "Info"
    $filteredData = $UserData
    $filtersApplied = @()
    
    # Filter by department
    if ($Department) {
        $filteredData = $filteredData | Where-Object { 
            $_.Department -like "*$Department*" -or 
            $_.DisplayName -like "*$Department*"
        }
        $filtersApplied += "Department: $Department"
    }
    
    # Filter by location
    if ($Location) {
        $filteredData = $filteredData | Where-Object { 
            $_.Location -like "*$Location*" -or 
            $_.OfficeLocation -like "*$Location*"
        }
        $filtersApplied += "Location: $Location"
    }
    
    # Filter by job title
    if ($JobTitle) {
        $filteredData = $filteredData | Where-Object { 
            $_.JobTitle -like "*$JobTitle*"
        }
        $filtersApplied += "Job Title: $JobTitle"
    }
    
    # Filter by last login after date
    if ($LoginAfter -and $LoginAfter -ne [DateTime]::MinValue) {
        $filteredData = $filteredData | Where-Object { 
            $_.TimeStamp -and $_.TimeStamp -ne [DateTime]::MinValue -and $_.TimeStamp -gt $LoginAfter
        }
        $filtersApplied += "Login After: $($LoginAfter.ToString('yyyy-MM-dd'))"
    }
    
    # Filter by last login before date
    if ($LoginBefore -and $LoginBefore -ne [DateTime]::MinValue) {
        $filteredData = $filteredData | Where-Object { 
            $_.TimeStamp -and $_.TimeStamp -ne [DateTime]::MinValue -and $_.TimeStamp -lt $LoginBefore
        }
        $filtersApplied += "Login Before: $($LoginBefore.ToString('yyyy-MM-dd'))"
    }
    
    # Filter by risk level
    if ($RiskLevel) {
        $filteredData = $filteredData | Where-Object { 
            $_.RiskLevel -eq $RiskLevel
        }
        $filtersApplied += "Risk Level: $RiskLevel"
    }
    
    # Filter for users without MFA
    if ($OnlyNoMFA) {
        $filteredData = $filteredData | Where-Object { 
            $_.MFAStatus -eq "No Methods Registered" -or 
            $_.MFAStatus -eq "Unknown" -or 
            -not $_.MFAStatus
        }
        $filtersApplied += "Only No MFA"
    }
    
    # Filter for privileged accounts
    if ($OnlyPrivileged) {
        $filteredData = $filteredData | Where-Object { 
            $_.IsPrivileged -eq $true -or 
            $_.UserRights -like "*Admin*" -or 
            $_.Roles -like "*Admin*"
        }
        $filtersApplied += "Only Privileged"
    }
    
    # Filter for disabled accounts
    if ($OnlyDisabled) {
        $filteredData = $filteredData | Where-Object { 
            $_.Status -eq "Disabled" -or 
            $_.Enabled -eq $false
        }
        $filtersApplied += "Only Disabled"
    }
    
    # Filter for guest users
    if ($OnlyGuests) {
        $filteredData = $filteredData | Where-Object { 
            $_.IsGuestUser -eq $true -or 
            $_.UserName -like "*#EXT#*"
        }
        $filtersApplied += "Only Guests"
    }
    
    # Filter for inactive accounts
    if ($InactiveDays -gt 0) {
        $inactiveDate = (Get-Date).AddDays(-$InactiveDays)
        $filteredData = $filteredData | Where-Object { 
            $_.TimeStamp -eq [DateTime]::MinValue -or 
            ($_.TimeStamp -and $_.TimeStamp -lt $inactiveDate)
        }
        $filtersApplied += "Inactive: $InactiveDays days+"
    }
    
    if ($filtersApplied.Count -gt 0) {
        Write-OperationStatus "Filters applied: $($filtersApplied -join ', ')" "Success"
        Write-OperationStatus "Filtered from $($UserData.Count) to $($filteredData.Count) users" "Success"
    } else {
        Write-OperationStatus "No filters applied" "Info"
    }
    
    return $filteredData
}
#endregion

#region Caching Functions
# Function to get cache file path
function Get-CacheFilePath {
    param(
        [string]$CacheKey
    )
    
    $cacheDir = Join-Path $env:TEMP "ITAuditKit_Cache"
    if (-not (Test-Path $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    }
    
    $sanitizedKey = $CacheKey -replace '[\\/:*?"<>|]', '_'
    return Join-Path $cacheDir "$sanitizedKey.cache.json"
}

# Function to save data to cache
function Save-ToCache {
    param(
        [string]$CacheKey,
        [object]$Data
    )
    
    try {
        $cachePath = Get-CacheFilePath -CacheKey $CacheKey
        $cacheObject = @{
            Timestamp = Get-Date
            Data = $Data
        }
        
        $cacheObject | ConvertTo-Json -Depth 100 | Out-File -FilePath $cachePath -Encoding UTF8
        Write-OperationStatus "Data cached to: $cachePath" "Success"
        return $true
    } catch {
        Write-OperationStatus "Failed to cache data: $($_.Exception.Message)" "Warning"
        return $false
    }
}

# Function to load data from cache
function Get-FromCache {
    param(
        [string]$CacheKey,
        [int]$ExpiryMinutes = 60
    )
    
    try {
        $cachePath = Get-CacheFilePath -CacheKey $CacheKey
        
        if (-not (Test-Path $cachePath)) {
            Write-OperationStatus "Cache not found for key: $CacheKey" "Info"
            return $null
        }
        
        $cacheObject = Get-Content $cachePath -Raw | ConvertFrom-Json
        $cacheAge = (Get-Date) - [DateTime]$cacheObject.Timestamp
        
        if ($cacheAge.TotalMinutes -gt $ExpiryMinutes) {
            Write-OperationStatus "Cache expired (age: $([Math]::Round($cacheAge.TotalMinutes, 1)) minutes)" "Warning"
            return $null
        }
        
        Write-OperationStatus "Cache hit! (age: $([Math]::Round($cacheAge.TotalMinutes, 1)) minutes)" "Success"
        return $cacheObject.Data
    } catch {
        Write-OperationStatus "Failed to load cache: $($_.Exception.Message)" "Warning"
        return $null
    }
}

# Function to clear cache
function Clear-AuditCache {
    param(
        [string]$CacheKey
    )
    
    try {
        if ($CacheKey) {
            $cachePath = Get-CacheFilePath -CacheKey $CacheKey
            if (Test-Path $cachePath) {
                Remove-Item $cachePath -Force
                Write-OperationStatus "Cache cleared for key: $CacheKey" "Success"
            }
        } else {
            $cacheDir = Join-Path $env:TEMP "ITAuditKit_Cache"
            if (Test-Path $cacheDir) {
                Get-ChildItem $cacheDir -Filter "*.cache.json" | Remove-Item -Force
                Write-OperationStatus "All cache files cleared" "Success"
            }
        }
        return $true
    } catch {
        Write-OperationStatus "Failed to clear cache: $($_.Exception.Message)" "Error"
        return $false
    }
}
#endregion

#region Compliance Reporting Functions
# Function to generate structured compliance data
function Get-ComplianceData {
    param(
        [array]$UserData,
        [string[]]$Frameworks
    )
    
    if (-not $UserData -or $UserData.Count -eq 0) {
        return @()
    }
    
    $complianceData = @()
    
    foreach ($framework in $Frameworks) {
        $frameworkData = switch ($framework) {
            "SOX" { Get-ComplianceData-SOX -UserData $UserData }
            "HIPAA" { Get-ComplianceData-HIPAA -UserData $UserData }
            "GDPR" { Get-ComplianceData-GDPR -UserData $UserData }
            "PCI-DSS" { Get-ComplianceData-PCIDSS -UserData $UserData }
            "ISO27001" { Get-ComplianceData-ISO27001 -UserData $UserData }
            "NIST" { Get-ComplianceData-NIST -UserData $UserData }
            "CIS" { Get-ComplianceData-CIS -UserData $UserData }
            "All" {
                $allData = @()
                $allData += Get-ComplianceData-SOX -UserData $UserData
                $allData += Get-ComplianceData-HIPAA -UserData $UserData
                $allData += Get-ComplianceData-GDPR -UserData $UserData
                $allData += Get-ComplianceData-PCIDSS -UserData $UserData
                $allData += Get-ComplianceData-ISO27001 -UserData $UserData
                $allData += Get-ComplianceData-NIST -UserData $UserData
                $allData += Get-ComplianceData-CIS -UserData $UserData
                $allData
            }
        }
        
        if ($framework -ne "All") {
            $complianceData += $frameworkData
        } else {
            $complianceData = $frameworkData
        }
    }
    
    return $complianceData
}

# Function to generate compliance report
function New-ComplianceReport {
    param(
        [array]$UserData,
        [string[]]$Frameworks
    )
    
    if (-not $UserData -or $UserData.Count -eq 0) {
        Write-OperationStatus "No user data available for compliance report" "Warning"
        return
    }
    
    foreach ($framework in $Frameworks) {
        Write-Host "`n" + "="*80 -ForegroundColor Cyan
        Write-Host "COMPLIANCE REPORT: $framework" -ForegroundColor Cyan
        Write-Host "="*80 -ForegroundColor Cyan
        Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        Write-Host "Total Users Analyzed: $($UserData.Count)" -ForegroundColor Gray
        Write-Host ""
        
        switch ($framework) {
            "SOX" {
                Write-ComplianceReport-SOX -UserData $UserData
            }
            "HIPAA" {
                Write-ComplianceReport-HIPAA -UserData $UserData
            }
            "GDPR" {
                Write-ComplianceReport-GDPR -UserData $UserData
            }
            "PCI-DSS" {
                Write-ComplianceReport-PCIDSS -UserData $UserData
            }
            "ISO27001" {
                Write-ComplianceReport-ISO27001 -UserData $UserData
            }
            "NIST" {
                Write-ComplianceReport-NIST -UserData $UserData
            }
            "CIS" {
                Write-ComplianceReport-CIS -UserData $UserData
            }
            "All" {
                Write-ComplianceReport-SOX -UserData $UserData
                Write-Host "`n" + "-"*80 -ForegroundColor Gray
                Write-ComplianceReport-HIPAA -UserData $UserData
                Write-Host "`n" + "-"*80 -ForegroundColor Gray
                Write-ComplianceReport-GDPR -UserData $UserData
                Write-Host "`n" + "-"*80 -ForegroundColor Gray
                Write-ComplianceReport-PCIDSS -UserData $UserData
                Write-Host "`n" + "-"*80 -ForegroundColor Gray
                Write-ComplianceReport-ISO27001 -UserData $UserData
                Write-Host "`n" + "-"*80 -ForegroundColor Gray
                Write-ComplianceReport-NIST -UserData $UserData
                Write-Host "`n" + "-"*80 -ForegroundColor Gray
                Write-ComplianceReport-CIS -UserData $UserData
            }
        }
        
        Write-Host "`n" + "="*80 -ForegroundColor Cyan
    }
}

# Get SOX Compliance Data
function Get-ComplianceData-SOX {
    param([array]$UserData)
    
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $adminAccounts = ($UserData | Where-Object { $_.UserRights -like "*Admin*" }).Count
    $sharedAccounts = ($UserData | Where-Object { $_.UserName -like "*shared*" -or $_.UserName -like "*admin*" -or $_.UserName -like "*service*" }).Count
    $inactivePrivileged = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.TimeStamp -eq [DateTime]::MinValue -or $_.TimeStamp -lt (Get-Date).AddDays(-90)) }).Count
    
    $soxCompliance = if ($privilegedNoMFA -eq 0 -and $inactivePrivileged -eq 0) { "PASS" } else { "FAIL" }
    
    return [PSCustomObject]@{
        Framework = "SOX"
        FrameworkName = "Sarbanes-Oxley Act"
        Focus = "Financial data integrity, access controls, segregation of duties"
        TotalUsers = $UserData.Count
        PrivilegedAccounts = $privilegedUsers
        AdminAccounts = $adminAccounts
        PrivilegedNoMFA = $privilegedNoMFA
        PrivilegedNoMFAStatus = if ($privilegedNoMFA -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        SharedAccounts = $sharedAccounts
        SharedAccountsStatus = if ($sharedAccounts -eq 0) { "COMPLIANT" } else { "REVIEW REQUIRED" }
        InactivePrivileged = $inactivePrivileged
        InactivePrivilegedStatus = if ($inactivePrivileged -eq 0) { "COMPLIANT" } else { "ACTION REQUIRED" }
        OverallStatus = $soxCompliance
        Timestamp = Get-Date
    }
}

# SOX Compliance Report
function Write-ComplianceReport-SOX {
    param([array]$UserData)
    
    Write-Host "[SOX - Sarbanes-Oxley Act]" -ForegroundColor Yellow
    Write-Host "Focus: Financial data integrity, access controls, segregation of duties" -ForegroundColor Gray
    Write-Host ""
    
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $adminAccounts = ($UserData | Where-Object { $_.UserRights -like "*Admin*" }).Count
    $sharedAccounts = ($UserData | Where-Object { $_.UserName -like "*shared*" -or $_.UserName -like "*admin*" -or $_.UserName -like "*service*" }).Count
    $inactivePrivileged = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.TimeStamp -eq [DateTime]::MinValue -or $_.TimeStamp -lt (Get-Date).AddDays(-90)) }).Count
    
    Write-Host "  Control Point: Access Controls" -ForegroundColor Cyan
    Write-Host "    Privileged Accounts: $privilegedUsers" -ForegroundColor White
    Write-Host "    Admin Accounts: $adminAccounts" -ForegroundColor White
    Write-Host "    Privileged without MFA: $privilegedNoMFA $(if ($privilegedNoMFA -gt 0) { '[NON-COMPLIANT]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($privilegedNoMFA -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  Control Point: Segregation of Duties" -ForegroundColor Cyan
    Write-Host "    Shared/Generic Accounts: $sharedAccounts $(if ($sharedAccounts -gt 0) { '[REVIEW REQUIRED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($sharedAccounts -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  Control Point: Account Review" -ForegroundColor Cyan
    Write-Host "    Inactive Privileged (90+ days): $inactivePrivileged $(if ($inactivePrivileged -gt 0) { '[ACTION REQUIRED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($inactivePrivileged -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    $soxCompliance = if ($privilegedNoMFA -eq 0 -and $inactivePrivileged -eq 0) { "PASS" } else { "FAIL" }
    Write-Host "  Overall SOX Compliance: $soxCompliance" -ForegroundColor $(if ($soxCompliance -eq "PASS") { 'Green' } else { 'Red' })
}

# Get HIPAA Compliance Data
function Get-ComplianceData-HIPAA {
    param([array]$UserData)
    
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $guestUsers = ($UserData | Where-Object { $_.IsGuestUser -eq $true }).Count
    $guestNoMFA = ($UserData | Where-Object { $_.IsGuestUser -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $disabledAccounts = ($UserData | Where-Object { $_.Status -eq "Disabled" -or $_.Enabled -eq $false }).Count
    
    $hipaaCompliance = if ($mfaPercentage -ge 90 -and $guestNoMFA -eq 0) { "PASS" } else { "FAIL" }
    
    return [PSCustomObject]@{
        Framework = "HIPAA"
        FrameworkName = "Health Insurance Portability and Accountability Act"
        Focus = "Protected Health Information (PHI) access controls"
        TotalUsers = $totalUsers
        UsersWithMFA = $usersWithMFA
        MFAPercentage = $mfaPercentage
        MFAStatus = if ($mfaPercentage -ge 90) { "COMPLIANT" } else { "NON-COMPLIANT" }
        GuestUsers = $guestUsers
        GuestNoMFA = $guestNoMFA
        GuestNoMFAStatus = if ($guestNoMFA -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        DisabledAccounts = $disabledAccounts
        OverallStatus = $hipaaCompliance
        Timestamp = Get-Date
    }
}

# HIPAA Compliance Report
function Write-ComplianceReport-HIPAA {
    param([array]$UserData)
    
    Write-Host "[HIPAA - Health Insurance Portability and Accountability Act]" -ForegroundColor Yellow
    Write-Host "Focus: Protected Health Information (PHI) access controls" -ForegroundColor Gray
    Write-Host ""
    
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $guestUsers = ($UserData | Where-Object { $_.IsGuestUser -eq $true }).Count
    $guestNoMFA = ($UserData | Where-Object { $_.IsGuestUser -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $disabledAccounts = ($UserData | Where-Object { $_.Status -eq "Disabled" -or $_.Enabled -eq $false }).Count
    
    Write-Host "  Control Point: Authentication (§164.312(a)(2)(i))" -ForegroundColor Cyan
    Write-Host "    Users with MFA: $usersWithMFA / $totalUsers ($mfaPercentage%)" -ForegroundColor White
    Write-Host "    MFA Compliance: $(if ($mfaPercentage -ge 90) { '[COMPLIANT]' } else { '[NON-COMPLIANT]' })" -ForegroundColor $(if ($mfaPercentage -ge 90) { 'Green' } else { 'Red' })
    Write-Host ""
    
    Write-Host "  Control Point: External Access (§164.308(a)(4)(ii)(C))" -ForegroundColor Cyan
    Write-Host "    Guest/External Users: $guestUsers" -ForegroundColor White
    Write-Host "    Guest Users without MFA: $guestNoMFA $(if ($guestNoMFA -gt 0) { '[NON-COMPLIANT]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($guestNoMFA -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  Control Point: Termination Procedures (§164.308(a)(3)(ii)(C))" -ForegroundColor Cyan
    Write-Host "    Disabled Accounts: $disabledAccounts" -ForegroundColor White
    Write-Host ""
    
    $hipaaCompliance = if ($mfaPercentage -ge 90 -and $guestNoMFA -eq 0) { "PASS" } else { "FAIL" }
    Write-Host "  Overall HIPAA Compliance: $hipaaCompliance" -ForegroundColor $(if ($hipaaCompliance -eq "PASS") { 'Green' } else { 'Red' })
}

# Get GDPR Compliance Data
function Get-ComplianceData-GDPR {
    param([array]$UserData)
    
    $guestUsers = ($UserData | Where-Object { $_.IsGuestUser -eq $true }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    $disabledUsers = ($UserData | Where-Object { $_.Status -eq "Disabled" -or $_.Enabled -eq $false }).Count
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    
    $gdprCompliance = if ($privilegedNoMFA -eq 0) { "PASS" } else { "FAIL" }
    
    return [PSCustomObject]@{
        Framework = "GDPR"
        FrameworkName = "General Data Protection Regulation"
        Focus = "Data subject rights, access control, data minimization"
        TotalUsers = $UserData.Count
        InactiveUsers = $inactiveUsers
        InactiveUsersStatus = if ($inactiveUsers -eq 0) { "COMPLIANT" } else { "REVIEW REQUIRED" }
        DisabledUsers = $disabledUsers
        DisabledUsersStatus = if ($disabledUsers -eq 0) { "COMPLIANT" } else { "CLEANUP NEEDED" }
        GuestUsers = $guestUsers
        PrivilegedUsers = $privilegedUsers
        PrivilegedNoMFA = $privilegedNoMFA
        PrivilegedNoMFAStatus = if ($privilegedNoMFA -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        OverallStatus = $gdprCompliance
        Timestamp = Get-Date
    }
}

# GDPR Compliance Report
function Write-ComplianceReport-GDPR {
    param([array]$UserData)
    
    Write-Host "[GDPR - General Data Protection Regulation]" -ForegroundColor Yellow
    Write-Host "Focus: Data subject rights, access control, data minimization" -ForegroundColor Gray
    Write-Host ""
    
    $guestUsers = ($UserData | Where-Object { $_.IsGuestUser -eq $true }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    $disabledUsers = ($UserData | Where-Object { $_.Status -eq "Disabled" -or $_.Enabled -eq $false }).Count
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    
    Write-Host "  Control Point: Data Minimization (Article 5(1)(c))" -ForegroundColor Cyan
    Write-Host "    Inactive Users (90+ days): $inactiveUsers $(if ($inactiveUsers -gt 0) { '[REVIEW REQUIRED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($inactiveUsers -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "    Disabled Accounts: $disabledUsers $(if ($disabledUsers -gt 0) { '[CLEANUP NEEDED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($disabledUsers -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  Control Point: Access Control (Article 32)" -ForegroundColor Cyan
    Write-Host "    Guest/External Users: $guestUsers" -ForegroundColor White
    Write-Host "    Privileged Accounts: $privilegedUsers" -ForegroundColor White
    Write-Host "    Privileged without MFA: $privilegedNoMFA $(if ($privilegedNoMFA -gt 0) { '[NON-COMPLIANT]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($privilegedNoMFA -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    $gdprCompliance = if ($privilegedNoMFA -eq 0) { "PASS" } else { "FAIL" }
    Write-Host "  Overall GDPR Compliance: $gdprCompliance" -ForegroundColor $(if ($gdprCompliance -eq "PASS") { 'Green' } else { 'Red' })
}

# Get PCI-DSS Compliance Data
function Get-ComplianceData-PCIDSS {
    param([array]$UserData)
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $oldPasswords = ($UserData | Where-Object { $_.PasswordLastSet -and ((Get-Date) - [DateTime]$_.PasswordLastSet).Days -gt 90 }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    $pciCompliance = if ($privilegedNoMFA -eq 0 -and $oldPasswords -eq 0 -and $inactiveUsers -eq 0) { "PASS" } else { "FAIL" }
    return [PSCustomObject]@{ Framework = "PCI-DSS"; FrameworkName = "Payment Card Industry Data Security Standard"; Focus = "Cardholder data protection"; TotalUsers = $totalUsers; UsersWithMFA = $usersWithMFA; MFAPercentage = $mfaPercentage; PrivilegedUsers = $privilegedUsers; PrivilegedNoMFA = $privilegedNoMFA; PrivilegedNoMFAStatus = if ($privilegedNoMFA -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }; OldPasswords = $oldPasswords; OldPasswordsStatus = if ($oldPasswords -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }; InactiveUsers = $inactiveUsers; InactiveUsersStatus = if ($inactiveUsers -eq 0) { "COMPLIANT" } else { "ACTION REQUIRED" }; OverallStatus = $pciCompliance; Timestamp = Get-Date }
}

function Get-ComplianceData-ISO27001 {
    param([array]$UserData)
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $sharedAccounts = ($UserData | Where-Object { $_.UserName -like "*shared*" -or $_.UserName -like "*admin*" -or $_.UserName -like "*service*" }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    $isoCompliance = if ($privilegedNoMFA -eq 0 -and $sharedAccounts -eq 0) { "PASS" } else { "FAIL" }
    return [PSCustomObject]@{ Framework = "ISO27001"; FrameworkName = "Information Security Management"; Focus = "Access control, authentication"; TotalUsers = $totalUsers; UsersWithMFA = $usersWithMFA; MFAPercentage = $mfaPercentage; InactiveUsers = $inactiveUsers; InactiveUsersStatus = if ($inactiveUsers -eq 0) { "COMPLIANT" } else { "REVIEW REQUIRED" }; SharedAccounts = $sharedAccounts; SharedAccountsStatus = if ($sharedAccounts -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }; PrivilegedUsers = $privilegedUsers; PrivilegedNoMFA = $privilegedNoMFA; PrivilegedNoMFAStatus = if ($privilegedNoMFA -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }; OverallStatus = $isoCompliance; Timestamp = Get-Date }
}

function Get-ComplianceData-NIST {
    param([array]$UserData)
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $highRiskUsers = ($UserData | Where-Object { $_.RiskLevel -eq "Critical" -or $_.RiskLevel -eq "High" }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    $nistCompliance = if ($mfaPercentage -ge 90 -and $highRiskUsers -eq 0) { "PASS" } else { "FAIL" }
    return [PSCustomObject]@{ Framework = "NIST"; FrameworkName = "NIST Cybersecurity Framework"; Focus = "Identify, Protect, Detect"; TotalUsers = $totalUsers; PrivilegedUsers = $privilegedUsers; UsersWithMFA = $usersWithMFA; MFAPercentage = $mfaPercentage; MFAStatus = if ($mfaPercentage -ge 90) { "COMPLIANT" } else { "NON-COMPLIANT" }; HighRiskUsers = $highRiskUsers; HighRiskUsersStatus = if ($highRiskUsers -eq 0) { "COMPLIANT" } else { "REVIEW REQUIRED" }; InactiveUsers = $inactiveUsers; InactiveUsersStatus = if ($inactiveUsers -eq 0) { "COMPLIANT" } else { "REVIEW REQUIRED" }; OverallStatus = $nistCompliance; Timestamp = Get-Date }
}

function Get-ComplianceData-CIS {
    param([array]$UserData)
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    $disabledUsers = ($UserData | Where-Object { $_.Status -eq "Disabled" -or $_.Enabled -eq $false }).Count
    $cisCompliance = if ($mfaPercentage -eq 100 -and $inactiveUsers -eq 0) { "PASS" } else { "FAIL" }
    return [PSCustomObject]@{ Framework = "CIS"; FrameworkName = "CIS Controls v8"; Focus = "Account management, MFA"; TotalUsers = $totalUsers; DisabledUsers = $disabledUsers; UsersWithMFA = $usersWithMFA; MFAPercentage = $mfaPercentage; InactiveUsers = $inactiveUsers; InactiveUsersStatus = if ($inactiveUsers -eq 0) { "COMPLIANT" } else { "ACTION REQUIRED" }; AllUsersMFAStatus = if ($mfaPercentage -eq 100) { "COMPLIANT" } else { "NON-COMPLIANT" }; PrivilegedUsers = $privilegedUsers; PrivilegedNoMFA = $privilegedNoMFA; PrivilegedNoMFAStatus = if ($privilegedNoMFA -eq 0) { "COMPLIANT" } else { "CRITICAL" }; OverallStatus = $cisCompliance; Timestamp = Get-Date }
}

# PCI-DSS Compliance Report
function Write-ComplianceReport-PCIDSS {
    param([array]$UserData)
    
    Write-Host "[PCI-DSS - Payment Card Industry Data Security Standard]" -ForegroundColor Yellow
    Write-Host "Focus: Cardholder data protection, strong access control" -ForegroundColor Gray
    Write-Host ""
    
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $oldPasswords = ($UserData | Where-Object { $_.PasswordLastSet -and ((Get-Date) - [DateTime]$_.PasswordLastSet).Days -gt 90 }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    
    Write-Host "  Requirement 8.3: Multi-Factor Authentication" -ForegroundColor Cyan
    Write-Host "    All Users with MFA: $usersWithMFA / $totalUsers ($mfaPercentage%)" -ForegroundColor White
    Write-Host "    Total Privileged Accounts: $privilegedUsers" -ForegroundColor White
    Write-Host "    Privileged without MFA: $privilegedNoMFA $(if ($privilegedNoMFA -gt 0) { '[NON-COMPLIANT]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($privilegedNoMFA -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  Requirement 8.2.4: Password Age (90 days)" -ForegroundColor Cyan
    Write-Host "    Users with old passwords (90+ days): $oldPasswords $(if ($oldPasswords -gt 0) { '[NON-COMPLIANT]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($oldPasswords -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  Requirement 8.1.4: Remove/Disable Inactive Accounts (90 days)" -ForegroundColor Cyan
    Write-Host "    Inactive Accounts (90+ days): $inactiveUsers $(if ($inactiveUsers -gt 0) { '[ACTION REQUIRED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($inactiveUsers -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    $pciCompliance = if ($privilegedNoMFA -eq 0 -and $oldPasswords -eq 0 -and $inactiveUsers -eq 0) { "PASS" } else { "FAIL" }
    Write-Host "  Overall PCI-DSS Compliance: $pciCompliance" -ForegroundColor $(if ($pciCompliance -eq "PASS") { 'Green' } else { 'Red' })
}

# ISO 27001 Compliance Report
function Write-ComplianceReport-ISO27001 {
    param([array]$UserData)
    
    Write-Host "[ISO 27001 - Information Security Management]" -ForegroundColor Yellow
    Write-Host "Focus: Access control, user management, authentication" -ForegroundColor Gray
    Write-Host ""
    
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $sharedAccounts = ($UserData | Where-Object { $_.UserName -like "*shared*" -or $_.UserName -like "*admin*" -or $_.UserName -like "*service*" }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    
    Write-Host "  A.9.2.1: User Registration" -ForegroundColor Cyan
    Write-Host "    Total Registered Users: $totalUsers" -ForegroundColor White
    Write-Host "    Inactive Users (90+ days): $inactiveUsers $(if ($inactiveUsers -gt 0) { '[REVIEW REQUIRED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($inactiveUsers -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  A.9.2.4: Management of Secret Authentication Information" -ForegroundColor Cyan
    Write-Host "    Users with MFA: $usersWithMFA / $totalUsers ($mfaPercentage%)" -ForegroundColor White
    Write-Host "    Shared Accounts: $sharedAccounts $(if ($sharedAccounts -gt 0) { '[NON-COMPLIANT]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($sharedAccounts -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  A.9.2.3: Management of Privileged Access Rights" -ForegroundColor Cyan
    Write-Host "    Total Privileged Accounts: $privilegedUsers" -ForegroundColor White
    Write-Host "    Privileged without MFA: $privilegedNoMFA $(if ($privilegedNoMFA -gt 0) { '[NON-COMPLIANT]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($privilegedNoMFA -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    $isoCompliance = if ($privilegedNoMFA -eq 0 -and $sharedAccounts -eq 0) { "PASS" } else { "FAIL" }
    Write-Host "  Overall ISO 27001 Compliance: $isoCompliance" -ForegroundColor $(if ($isoCompliance -eq "PASS") { 'Green' } else { 'Red' })
}

# NIST Compliance Report
function Write-ComplianceReport-NIST {
    param([array]$UserData)
    
    Write-Host "[NIST CSF - Cybersecurity Framework]" -ForegroundColor Yellow
    Write-Host "Focus: Identify, Protect, Detect, Respond, Recover" -ForegroundColor Gray
    Write-Host ""
    
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $highRiskUsers = ($UserData | Where-Object { $_.RiskLevel -eq "Critical" -or $_.RiskLevel -eq "High" }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    
    Write-Host "  PR.AC-1: Identities and Credentials" -ForegroundColor Cyan
    Write-Host "    Total User Identities: $totalUsers" -ForegroundColor White
    Write-Host "    Privileged Accounts: $privilegedUsers" -ForegroundColor White
    Write-Host ""
    
    Write-Host "  PR.AC-7: Users and Devices Authenticated" -ForegroundColor Cyan
    Write-Host "    Users with MFA: $usersWithMFA / $totalUsers ($mfaPercentage%)" -ForegroundColor White
    Write-Host "    MFA Compliance: $(if ($mfaPercentage -ge 90) { '[COMPLIANT]' } else { '[NON-COMPLIANT]' })" -ForegroundColor $(if ($mfaPercentage -ge 90) { 'Green' } else { 'Red' })
    Write-Host ""
    
    Write-Host "  DE.CM-1: Detect Unauthorized Access" -ForegroundColor Cyan
    Write-Host "    High Risk Users: $highRiskUsers $(if ($highRiskUsers -gt 0) { '[REVIEW REQUIRED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($highRiskUsers -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "    Inactive Accounts: $inactiveUsers $(if ($inactiveUsers -gt 0) { '[REVIEW REQUIRED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($inactiveUsers -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ""
    
    $nistCompliance = if ($mfaPercentage -ge 90 -and $highRiskUsers -eq 0) { "PASS" } else { "FAIL" }
    Write-Host "  Overall NIST CSF Compliance: $nistCompliance" -ForegroundColor $(if ($nistCompliance -eq "PASS") { 'Green' } else { 'Red' })
}

# CIS Controls Compliance Report
function Write-ComplianceReport-CIS {
    param([array]$UserData)
    
    Write-Host "[CIS Controls v8 - Critical Security Controls]" -ForegroundColor Yellow
    Write-Host "Focus: Account management, access control, MFA" -ForegroundColor Gray
    Write-Host ""
    
    $totalUsers = $UserData.Count
    $usersWithMFA = ($UserData | Where-Object { $_.MFAStatus -and $_.MFAStatus -ne "No Methods Registered" -and $_.MFAStatus -ne "Unknown" }).Count
    $mfaPercentage = if ($totalUsers -gt 0) { [Math]::Round(($usersWithMFA / $totalUsers) * 100, 1) } else { 0 }
    $privilegedUsers = ($UserData | Where-Object { $_.IsPrivileged -eq $true }).Count
    $privilegedNoMFA = ($UserData | Where-Object { $_.IsPrivileged -eq $true -and ($_.MFAStatus -eq "No Methods Registered" -or $_.MFAStatus -eq "Unknown") }).Count
    $inactiveUsers = ($UserData | Where-Object { $_.TimeStamp -lt (Get-Date).AddDays(-90) -or $_.TimeStamp -eq [DateTime]::MinValue }).Count
    $disabledUsers = ($UserData | Where-Object { $_.Status -eq "Disabled" -or $_.Enabled -eq $false }).Count
    
    Write-Host "  Control 5.1: Establish Unique Accounts" -ForegroundColor Cyan
    Write-Host "    Total User Accounts: $totalUsers" -ForegroundColor White
    Write-Host "    Disabled Accounts: $disabledUsers" -ForegroundColor White
    Write-Host ""
    
    Write-Host "  Control 5.2: Use Unique Passwords" -ForegroundColor Cyan
    Write-Host "    Users with MFA: $usersWithMFA / $totalUsers ($mfaPercentage%)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "  Control 5.3: Disable Dormant Accounts" -ForegroundColor Cyan
    Write-Host "    Inactive Accounts (90+ days): $inactiveUsers $(if ($inactiveUsers -gt 0) { '[ACTION REQUIRED]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($inactiveUsers -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    Write-Host "  Control 6.3: Require MFA for All Accounts" -ForegroundColor Cyan
    Write-Host "    All Users with MFA: $mfaPercentage% $(if ($mfaPercentage -eq 100) { '[COMPLIANT]' } else { '[NON-COMPLIANT]' })" -ForegroundColor $(if ($mfaPercentage -eq 100) { 'Green' } else { 'Red' })
    Write-Host "    Total Privileged Accounts: $privilegedUsers" -ForegroundColor White
    Write-Host "    Privileged without MFA: $privilegedNoMFA $(if ($privilegedNoMFA -gt 0) { '[CRITICAL]' } else { '[COMPLIANT]' })" -ForegroundColor $(if ($privilegedNoMFA -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    $cisCompliance = if ($mfaPercentage -eq 100 -and $inactiveUsers -eq 0) { "PASS" } else { "FAIL" }
    Write-Host "  Overall CIS Controls Compliance: $cisCompliance" -ForegroundColor $(if ($cisCompliance -eq "PASS") { 'Green' } else { 'Red' })
}
#endregion

# Function to load configuration from file
function Get-Configuration {
    param(
        [string]$ConfigPath
    )
    
    if (-not (Test-Path $ConfigPath)) {
        Write-OperationStatus "Configuration file not found: $ConfigPath" "Warning"
        return $null
    }
    
    try {
        $configContent = Get-Content $ConfigPath -Raw -Encoding UTF8
        $config = $configContent | ConvertFrom-Json
        Write-OperationStatus "Configuration loaded from: $ConfigPath" "Success"
        return $config
    } catch {
        Write-OperationStatus "Failed to load configuration: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Function to apply configuration profile
function Set-ConfigurationProfile {
    param(
        [string]$ProfileName
    )
    
    Write-OperationStatus "Applying security audit profile: $ProfileName" "Info"
    
    switch ($ProfileName) {
        "Quick" {
            $script:IncludeLocal = $false
            $script:IncludeAD = $false
            $script:IncludeEntraID = $true
            $script:ListUsers = $true
            $script:MaxRecords = 50
            $script:IncludeRiskScore = $true
            $script:Minimal = $true
            Write-OperationStatus "Quick profile: Entra ID users only, risk scoring, minimal output" "Success"
        }
        "Standard" {
            $script:IncludeLocal = $false
            $script:IncludeAD = $false
            $script:IncludeEntraID = $true
            $script:ListUsers = $true
            $script:MaxRecords = 200
            $script:IncludeRiskScore = $true
            $script:IncludePrivilegedAccounts = $true
            $script:IncludeServiceAccounts = $true
            $script:IncludePasswordPolicy = $true
            Write-OperationStatus "Standard profile: Entra ID users, risk analysis, privileged accounts, password policy" "Success"
        }
        "Comprehensive" {
            $script:IncludeLocal = $true
            $script:IncludeAD = $true
            $script:IncludeEntraID = $true
            $script:ListUsers = $true
            $script:MaxRecords = 500
            $script:IncludeRiskScore = $true
            $script:IncludePrivilegedAccounts = $true
            $script:IncludeServiceAccounts = $true
            $script:IncludeGuestUsers = $true
            $script:IncludePasswordPolicy = $true
            $script:IncludeAccountLockout = $true
            $script:IncludeGroupMembership = $true
            $script:IncludeAppPermissions = $true
            $script:IncludeDeviceCompliance = $true
            $script:IncludeConditionalAccess = $true
            $script:IncludeRiskySignins = $true
            Write-OperationStatus "Comprehensive profile: All sources, all analysis features" "Success"
        }
        "Executive" {
            $script:IncludeLocal = $false
            $script:IncludeAD = $false
            $script:IncludeEntraID = $true
            $script:ListUsers = $true
            $script:MaxRecords = 1000
            $script:IncludeRiskScore = $true
            $script:IncludePrivilegedAccounts = $true
            $script:IncludeServiceAccounts = $true
            $script:IncludeGuestUsers = $true
            $script:IncludePasswordPolicy = $true
            $script:IncludeExportFormats = $true
            $script:ExportExcel = $true
            Write-OperationStatus "Executive profile: High-level security overview with Excel export" "Success"
        }
        "Compliance" {
            $script:IncludeLocal = $false
            $script:IncludeAD = $false
            $script:IncludeEntraID = $true
            $script:ListUsers = $true
            $script:MaxRecords = 1000
            $script:IncludeRiskScore = $true
            $script:IncludePrivilegedAccounts = $true
            $script:IncludeServiceAccounts = $true
            $script:IncludeGuestUsers = $true
            $script:IncludePasswordPolicy = $true
            $script:IncludeAccountLockout = $true
            $script:IncludeGroupMembership = $true
            $script:IncludeAppPermissions = $true
            $script:IncludeDeviceCompliance = $true
            $script:IncludeConditionalAccess = $true
            $script:IncludeRiskySignins = $true
            $script:IncludeExportFormats = $true
            $script:ExportExcel = $true
            Write-OperationStatus "Compliance profile: Full audit trail for compliance reporting" "Success"
        }
        default {
            Write-OperationStatus "Unknown profile: $ProfileName" "Warning"
        }
    }
}

# Function to create default configuration file
function New-DefaultConfiguration {
    param(
        [string]$ConfigPath = ".\users.config.json"
    )
    
    $defaultConfig = @{
        "DefaultProfile" = "Standard"
        "MaxRecords" = 200
        "IncludeSources" = @{
            "Local" = $false
            "ActiveDirectory" = $false
            "EntraID" = $true
        }
        "AnalysisFeatures" = @{
            "RiskScore" = $true
            "PrivilegedAccounts" = $true
            "ServiceAccounts" = $true
            "GuestUsers" = $false
            "PasswordPolicy" = $true
            "AccountLockout" = $false
            "GroupMembership" = $false
            "AppPermissions" = $false
            "DeviceCompliance" = $false
            "ConditionalAccess" = $false
            "RiskySignins" = $false
        }
        "ExportOptions" = @{
            "Excel" = $false
            "MultipleFormats" = $false
            "DefaultPath" = ".\SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        }
        "DisplayOptions" = @{
            "Minimal" = $false
            "OutGridView" = $false
            "ShowSummary" = $true
        }
    }
    
    try {
        $defaultConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $ConfigPath -Encoding UTF8
        Write-OperationStatus "Default configuration created: $ConfigPath" "Success"
        return $true
    } catch {
        Write-OperationStatus "Failed to create configuration file: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Function to get local user rights
function Get-LocalUserRights {
    param(
        [string]$UserName
    )
    
    try {
        # Get local user groups
        $userGroups = @()
        $localGroups = Get-LocalGroup | Where-Object { $_.Name -notlike "*$" -and $_.Name -ne "Users" }
        
        foreach ($group in $localGroups) {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
            if ($members) {
                foreach ($member in $members) {
                    if ($member.Name -like "*$UserName" -or $member.Name -eq $UserName) {
                        $userGroups += $group.Name
                        break
                    }
                }
            }
        }
        
        # Check for built-in administrators
        if ($userGroups -contains "Administrators") {
            return "Administrator"
        }
        
        # Check for other important groups
        $importantGroups = @("Remote Desktop Users", "Power Users", "Backup Operators", "Network Configuration Operators")
        $foundGroups = $userGroups | Where-Object { $_ -in $importantGroups }
        
        if ($foundGroups.Count -gt 0) {
            return ($foundGroups -join ", ")
        }
        
        # Check if user is in any local groups (excluding default Users group)
        $nonDefaultGroups = $userGroups | Where-Object { $_ -ne "Users" }
        if ($nonDefaultGroups.Count -gt 0) {
            return ($nonDefaultGroups -join ", ")
        }
        
        return "Standard User"
        
    } catch {
        Write-Verbose "Could not retrieve user rights for $UserName : $($_.Exception.Message)"
        return "Unknown"
    }
}

# Function to get local user MFA status
function Get-LocalUserMFAStatus {
    param(
        [string]$UserName
    )
    
    try {
        # Check if Windows Hello is configured for the user
        $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
        if ($user) {
            # Check if user has Windows Hello configured (this is a simplified check)
            # In a real environment, you'd check the NGC (Next Generation Credentials) store
            $ngcPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Ngc"
            if (Test-Path $ngcPath) {
                # Check if there are any NGC keys for this user
                $ngcKeys = Get-ChildItem $ngcPath -ErrorAction SilentlyContinue
                if ($ngcKeys) {
                    return "Windows Hello Available"
                }
            }
            
            # Check if user has a password set (basic MFA check)
            if ($user.PasswordRequired -eq $false) {
                return "No Password Required"
            }
            
            return "Password Only"
        }
        
        return "Unknown"
        
    } catch {
        Write-Verbose "Could not retrieve MFA status for $UserName : $($_.Exception.Message)"
        return "Unknown"
    }
}

# Function to get local user PIN last set date
function Get-LocalUserPINLastSet {
    param(
        [string]$UserName
    )
    
    try {
        # Check Windows Hello PIN last set from registry
        $ngcPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Ngc"
        if (Test-Path $ngcPath) {
            # Look for NGC keys that might contain PIN information
            $ngcKeys = Get-ChildItem $ngcPath -ErrorAction SilentlyContinue
            if ($ngcKeys) {
                # This is a simplified approach - in reality, you'd need to parse NGC data
                # For now, we'll check if there are any recent NGC keys
                $latestKey = $ngcKeys | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($latestKey) {
                    return $latestKey.LastWriteTime
                }
            }
        }
        
        # Check Windows Hello for Business PIN from user profile
        $userProfilePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin"
        if (Test-Path $userProfilePath) {
            $pinKeys = Get-ChildItem $userProfilePath -ErrorAction SilentlyContinue
            if ($pinKeys) {
                $latestPin = $pinKeys | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($latestPin) {
                    return $latestPin.LastWriteTime
                }
            }
        }
        
        return $null
        
    } catch {
        Write-Verbose "Could not retrieve PIN last set for $UserName : $($_.Exception.Message)"
        return $null
    }
}

# Function to calculate security risk score
function Get-SecurityRiskScore {
    param(
        [PSCustomObject]$User
    )
    
    $riskScore = 0
    $riskFactors = @()
    
    # MFA Status Risk (0-30 points)
    if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
        $riskScore += 30
        $riskFactors += "No MFA"
    } elseif ($User.MFAStatus -like "*Password Only*") {
        $riskScore += 20
        $riskFactors += "Password Only"
    } elseif ($User.MFAStatus -like "*Windows Hello*" -and $User.MFAStatus -notlike "*Authenticator*" -and $User.MFAStatus -notlike "*Phone*") {
        $riskScore += 10
        $riskFactors += "Limited MFA"
    }
    
    # MFA Enforcement Risk (0-20 points)
    if ($User.MFAEnforcement -eq "Not Enforced" -or $User.MFAEnforcement -eq "Unknown") {
        $riskScore += 20
        $riskFactors += "MFA Not Enforced"
    }
    
    # Privileged Account Risk (0-40 points)
    if ($User.UserRights -like "*Global Administrator*" -or $User.UserRights -like "*Global Admin*") {
        $riskScore += 40
        $riskFactors += "Global Admin"
    } elseif ($User.UserRights -like "*Administrator*" -or $User.UserRights -like "*Admin*") {
        $riskScore += 30
        $riskFactors += "Admin Role"
    } elseif ($User.UserRights -like "*Privileged*") {
        $riskScore += 20
        $riskFactors += "Privileged Role"
    }
    
    # Password Age Risk (0-25 points)
    if ($User.PasswordLastSet) {
        $passwordAge = (Get-Date) - [DateTime]$User.PasswordLastSet
        if ($passwordAge.Days -gt 365) {
            $riskScore += 25
            $riskFactors += "Password 1yr+"
        } elseif ($passwordAge.Days -gt 180) {
            $riskScore += 15
            $riskFactors += "Password 6mo+"
        } elseif ($passwordAge.Days -gt 90) {
            $riskScore += 10
            $riskFactors += "Password 3mo+"
        }
    } else {
        $riskScore += 15
        $riskFactors += "Unknown Password Age"
    }
    
    # Account Activity Risk (0-20 points)
    if ($User.TimeStamp -eq [DateTime]::MinValue) {
        $riskScore += 20
        $riskFactors += "Never Logged In"
    } else {
        $lastLogin = (Get-Date) - [DateTime]$User.TimeStamp
        if ($lastLogin.Days -gt 90) {
            $riskScore += 15
            $riskFactors += "Inactive 90d+"
        } elseif ($lastLogin.Days -gt 30) {
            $riskScore += 10
            $riskFactors += "Inactive 30d+"
        }
    }
    
    # Account Status Risk (0-15 points)
    if ($User.Status -eq "Disabled") {
        $riskScore += 5
        $riskFactors += "Disabled Account"
    }
    
    # Guest User Risk (0-10 points)
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*guest*") {
        $riskScore += 10
        $riskFactors += "Guest User"
    }
    
    # Determine risk level
    $riskLevel = if ($riskScore -ge 70) { "Critical" }
                 elseif ($riskScore -ge 50) { "High" }
                 elseif ($riskScore -ge 30) { "Medium" }
                 elseif ($riskScore -ge 15) { "Low" }
                 else { "Minimal" }
    
    return @{
        Score = $riskScore
        Level = $riskLevel
        Factors = $riskFactors -join ", "
    }
}

# Function to analyze privileged accounts
function Get-PrivilegedAccountAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $privilegeLevel = "Standard"
    $privilegeRisks = @()
    
    # Check for Global Administrator
    if ($User.UserRights -like "*Global Administrator*" -or $User.UserRights -like "*Global Admin*") {
        $privilegeLevel = "Global Administrator"
        $privilegeRisks += "Highest privilege level"
        if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
            $privilegeRisks += "No MFA on Global Admin"
        }
        if ($User.MFAEnforcement -eq "Not Enforced") {
            $privilegeRisks += "MFA not enforced"
        }
    }
    # Check for other admin roles
    elseif ($User.UserRights -like "*User Administrator*" -or $User.UserRights -like "*User Admin*") {
        $privilegeLevel = "User Administrator"
        $privilegeRisks += "Can manage users"
    }
    elseif ($User.UserRights -like "*Application Administrator*" -or $User.UserRights -like "*App Admin*") {
        $privilegeLevel = "Application Administrator"
        $privilegeRisks += "Can manage applications"
    }
    elseif ($User.UserRights -like "*Security Administrator*" -or $User.UserRights -like "*Security Admin*") {
        $privilegeLevel = "Security Administrator"
        $privilegeRisks += "Can manage security policies"
    }
    elseif ($User.UserRights -like "*Privileged Role Administrator*" -or $User.UserRights -like "*Privileged Role Admin*") {
        $privilegeLevel = "Privileged Role Administrator"
        $privilegeRisks += "Can manage privileged roles"
    }
    elseif ($User.UserRights -like "*Administrator*" -or $User.UserRights -like "*Admin*") {
        $privilegeLevel = "Administrator"
        $privilegeRisks += "Administrative privileges"
    }
    elseif ($User.UserRights -like "*Privileged*") {
        $privilegeLevel = "Privileged User"
        $privilegeRisks += "Elevated privileges"
    }
    
    # Check for additional risks
    if ($User.Status -eq "Disabled" -and $privilegeLevel -ne "Standard") {
        $privilegeRisks += "Disabled privileged account"
    }
    
    if ($User.TimeStamp -eq [DateTime]::MinValue -and $privilegeLevel -ne "Standard") {
        $privilegeRisks += "Privileged account never used"
    }
    
    return @{
        Level = $privilegeLevel
        Risks = $privilegeRisks -join ", "
        IsPrivileged = $privilegeLevel -ne "Standard"
    }
}

# Function to analyze service accounts
function Get-ServiceAccountAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $accountType = "User Account"
    $serviceRisks = @()
    $isServiceAccount = $false
    
    # Check for service account indicators
    if ($User.UserName -like "*svc*" -or $User.UserName -like "*service*" -or $User.UserName -like "*app*") {
        $accountType = "Service Account"
        $isServiceAccount = $true
        $serviceRisks += "Service account naming"
    }
    
    # Check for application accounts (Entra ID)
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") {
        $accountType = "Guest/External Account"
        $isServiceAccount = $true
        $serviceRisks += "External account"
    }
    
    # Check for non-interactive accounts
    if ($User.AppDisplayName -eq "Non-Interactive" -or $User.AppDisplayName -eq "Service Principal") {
        $accountType = "Non-Interactive Account"
        $isServiceAccount = $true
        $serviceRisks += "Non-interactive access"
    }
    
    # Check for accounts with no recent activity
    if ($User.TimeStamp -ne [DateTime]::MinValue) {
        $lastActivity = (Get-Date) - [DateTime]$User.TimeStamp
        if ($lastActivity.Days -gt 365) {
            $serviceRisks += "No activity 1yr+"
        } elseif ($lastActivity.Days -gt 180) {
            $serviceRisks += "No activity 6mo+"
        }
    } else {
        $serviceRisks += "Never logged in"
    }
    
    # Check for service account risks
    if ($isServiceAccount) {
        if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
            $serviceRisks += "No MFA on service account"
        }
        if ($User.UserRights -like "*Administrator*" -or $User.UserRights -like "*Admin*") {
            $serviceRisks += "Service account with admin rights"
        }
        if ($User.Status -eq "Enabled" -and $User.TimeStamp -eq [DateTime]::MinValue) {
            $serviceRisks += "Enabled but never used"
        }
    }
    
    return @{
        Type = $accountType
        IsServiceAccount = $isServiceAccount
        Risks = $serviceRisks -join ", "
    }
}

# Function to analyze guest users
function Get-GuestUserAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $guestStatus = "Regular User"
    $guestRisks = @()
    $isGuestUser = $false
    $accessExpiration = $null
    
    # Check for guest user indicators
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") {
        $guestStatus = "Guest User"
        $isGuestUser = $true
        $guestRisks += "External access"
        
        # Try to extract expiration date from username or additional properties
        # This is a simplified approach - in reality you'd query the user object for actual expiration
        if ($User.PSObject.Properties.Name -contains 'ExternalUserState') {
            $guestRisks += "External state: $($User.ExternalUserState)"
        }
    }
    
    # Check for guest user risks
    if ($isGuestUser) {
        # Check for admin privileges on guest accounts
        if ($User.UserRights -like "*Administrator*" -or $User.UserRights -like "*Admin*") {
            $guestRisks += "Guest with admin rights"
        }
        
        # Check for MFA status on guest accounts
        if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
            $guestRisks += "No MFA on guest account"
        }
        
        # Check for recent activity
        if ($User.TimeStamp -ne [DateTime]::MinValue) {
            $lastActivity = (Get-Date) - [DateTime]$User.TimeStamp
            if ($lastActivity.Days -gt 90) {
                $guestRisks += "Inactive guest 90d+"
            } elseif ($lastActivity.Days -gt 30) {
                $guestRisks += "Inactive guest 30d+"
            }
        } else {
            $guestRisks += "Guest never accessed"
        }
        
        # Check account status
        if ($User.Status -eq "Disabled") {
            $guestRisks += "Disabled guest account"
        }
        
        # Check for password age (guests often have old passwords)
        if ($User.PasswordLastSet) {
            $passwordAge = (Get-Date) - [DateTime]$User.PasswordLastSet
            if ($passwordAge.Days -gt 180) {
                $guestRisks += "Old guest password"
            }
        }
    }
    
    # Check for other external indicators
    if ($User.UserName -like "*guest*" -or $User.UserName -like "*external*") {
        if (-not $isGuestUser) {
            $guestStatus = "Potential Guest"
            $isGuestUser = $true
            $guestRisks += "Guest naming convention"
        }
    }
    
    return @{
        Status = $guestStatus
        IsGuestUser = $isGuestUser
        Risks = $guestRisks -join ", "
        AccessExpiration = $accessExpiration
    }
}

# Function to get risk score color
function Get-RiskScoreColor {
    param(
        [int]$Score
    )
    
    if ($Score -ge 70) { return "Red" }
    elseif ($Score -ge 50) { return "DarkRed" }
    elseif ($Score -ge 30) { return "Yellow" }
    elseif ($Score -ge 15) { return "Green" }
    else { return "DarkGreen" }
}

# Function to get risk level color
function Get-RiskLevelColor {
    param(
        [string]$Level
    )
    
    if ($Level -eq "Critical") { return "Red" }
    elseif ($Level -eq "High") { return "DarkRed" }
    elseif ($Level -eq "Medium") { return "Yellow" }
    elseif ($Level -eq "Low") { return "Green" }
    elseif ($Level -eq "Minimal") { return "DarkGreen" }
    else { return "White" }
}

# Function to get password policy score color
function Get-PasswordScoreColor {
    param(
        [int]$Score
    )
    
    if ($Score -ge 90) { return "DarkGreen" }      # Compliant - Dark Green
    elseif ($Score -ge 75) { return "Green" }      # Minor Issues - Green
    elseif ($Score -ge 60) { return "Yellow" }     # Non-Compliant - Yellow
    elseif ($Score -ge 40) { return "Red" }        # High Risk - Red
    else { return "DarkRed" }                      # Critical - Dark Red
}

# Function to get password policy level color
function Get-PasswordLevelColor {
    param(
        [string]$Level
    )
    
    if ($Level -eq "Compliant") { return "DarkGreen" }
    elseif ($Level -eq "Minor Issues") { return "Green" }
    elseif ($Level -eq "Non-Compliant") { return "Yellow" }
    elseif ($Level -eq "High Risk") { return "Red" }
    elseif ($Level -eq "Critical") { return "DarkRed" }
    else { return "White" }
}

# Function to get lockout score color
function Get-LockoutScoreColor {
    param(
        [int]$Score
    )
    
    if ($Score -ge 90) { return "DarkGreen" }      # Low lockout risk - Dark Green
    elseif ($Score -ge 75) { return "Green" }      # Minimal lockout risk - Green
    elseif ($Score -ge 60) { return "Yellow" }     # Moderate lockout risk - Yellow
    elseif ($Score -ge 40) { return "Red" }        # High lockout risk - Red
    else { return "DarkRed" }                      # Critical lockout risk - Dark Red
}

# Function to analyze password policy compliance
function Get-PasswordPolicyAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $policyViolations = @()
    $policyScore = 100  # Start with perfect score, deduct for violations
    
    # Check password age
    if ($User.PasswordLastSet) {
        $passwordAge = (Get-Date) - [DateTime]$User.PasswordLastSet
        
        if ($passwordAge.Days -gt 365) {
            $policyViolations += "Password 1yr+ old"
            $policyScore -= 30
        } elseif ($passwordAge.Days -gt 180) {
            $policyViolations += "Password 6mo+ old"
            $policyScore -= 15
        } elseif ($passwordAge.Days -gt 90) {
            $policyViolations += "Password 3mo+ old"
            $policyScore -= 5
        }
    } else {
        $policyViolations += "No password age data"
        $policyScore -= 10
    }
    
    # Check for password never changed (common security issue)
    if ($User.PasswordLastSet -and [DateTime]$User.PasswordLastSet -eq [DateTime]::MinValue) {
        $policyViolations += "Password never changed"
        $policyScore -= 25
    }
    
    # Check for accounts that should have password policies
    if ($User.UserRights -like "*Administrator*" -or $User.UserRights -like "*Admin*") {
        if ($User.PasswordLastSet) {
            $passwordAge = (Get-Date) - [DateTime]$User.PasswordLastSet
            if ($passwordAge.Days -gt 90) {
                $policyViolations += "Admin password >90d"
                $policyScore -= 20
            }
        }
    }
    
    # Check for service accounts with old passwords
    if ($User.UserName -like "*svc*" -or $User.UserName -like "*service*" -or $User.UserName -like "*app*") {
        if ($User.PasswordLastSet) {
            $passwordAge = (Get-Date) - [DateTime]$User.PasswordLastSet
            if ($passwordAge.Days -gt 180) {
                $policyViolations += "Service account password 180d+"
                $policyScore -= 15
            }
        }
    }
    
    # Check for guest accounts with old passwords
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") {
        if ($User.PasswordLastSet) {
            $passwordAge = (Get-Date) - [DateTime]$User.PasswordLastSet
            if ($passwordAge.Days -gt 90) {
                $policyViolations += "Guest password 90d+"
                $policyScore -= 10
            }
        }
    }
    
    # Determine compliance level
    $complianceLevel = switch ($policyScore) {
        {$_ -ge 90} { "Compliant" }
        {$_ -ge 75} { "Minor Issues" }
        {$_ -ge 60} { "Non-Compliant" }
        {$_ -ge 40} { "High Risk" }
        default { "Critical" }
    }
    
    return @{
        Score = [Math]::Max(0, $policyScore)
        Level = $complianceLevel
        Violations = $policyViolations -join ", "
        HasViolations = $policyViolations.Count -gt 0
    }
}

# Function to analyze account lockout events
function Get-AccountLockoutAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $lockoutRisks = @()
    $lockoutScore = 100
    
    # This is a simplified analysis - in reality you'd query event logs
    # For now, we'll analyze based on available data
    
    # Check for accounts that might be prone to lockouts
    if ($User.UserName -like "*svc*" -or $User.UserName -like "*service*") {
        $lockoutRisks += "Service account (potential lockout risk)"
        $lockoutScore -= 10
    }
    
    # Check for accounts with no recent activity (might indicate lockout issues)
    if ($User.TimeStamp -eq [DateTime]::MinValue) {
        $lockoutRisks += "Never logged in (potential lockout)"
        $lockoutScore -= 20
    } elseif ($User.TimeStamp) {
        $lastActivity = (Get-Date) - [DateTime]$User.TimeStamp
        if ($lastActivity.Days -gt 30) {
            $lockoutRisks += "Inactive 30d+ (potential lockout)"
            $lockoutScore -= 15
        }
    }
    
    # Check for disabled accounts (might be due to lockouts)
    if ($User.Status -eq "Disabled") {
        $lockoutRisks += "Account disabled (possible lockout)"
        $lockoutScore -= 25
    }
    
    return @{
        Score = [Math]::Max(0, $lockoutScore)
        Risks = $lockoutRisks -join ", "
        HasRisks = $lockoutRisks.Count -gt 0
    }
}

# Function to analyze group memberships
function Get-GroupMembershipAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $groupRisks = @()
    $groupScore = 100
    
    # Analyze role memberships for security risks
    if ($User.Roles) {
        $roles = $User.Roles -split ","
        
        # Check for excessive privileges
        if ($roles.Count -gt 5) {
            $groupRisks += "Excessive role memberships ($($roles.Count))"
            $groupScore -= 15
        }
        
        # Check for dangerous role combinations
        $hasGlobalAdmin = $User.Roles -like "*Global Administrator*" -or $User.Roles -like "*Global Admin*"
        $hasUserAdmin = $User.Roles -like "*User Administrator*" -or $User.Roles -like "*User Admin*"
        $hasAppAdmin = $User.Roles -like "*Application Administrator*" -or $User.Roles -like "*App Admin*"
        
        if ($hasGlobalAdmin -and $hasUserAdmin) {
            $groupRisks += "Global + User Admin roles"
            $groupScore -= 20
        }
        
        if ($hasGlobalAdmin -and $hasAppAdmin) {
            $groupRisks += "Global + App Admin roles"
            $groupScore -= 20
        }
        
        # Check for service accounts with admin roles
        if (($User.UserName -like "*svc*" -or $User.UserName -like "*service*") -and $hasGlobalAdmin) {
            $groupRisks += "Service account with Global Admin"
            $groupScore -= 30
        }
        
        # Check for guest accounts with admin roles
        if (($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") -and $hasGlobalAdmin) {
            $groupRisks += "Guest account with Global Admin"
            $groupScore -= 35
        }
    }
    
    return @{
        Score = [Math]::Max(0, $groupScore)
        Risks = $groupRisks -join ", "
        HasRisks = $groupRisks.Count -gt 0
    }
}

# Function to analyze application permissions
function Get-AppPermissionsAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $appRisks = @()
    $appScore = 100
    
    # This is a simplified analysis - in reality you'd query Microsoft Graph for actual app permissions
    # For now, we'll analyze based on available data and common patterns
    
    # Check for users with application-related roles
    if ($User.Roles) {
        $hasAppAdmin = $User.Roles -like "*Application Administrator*" -or $User.Roles -like "*App Admin*"
        $hasCloudAppAdmin = $User.Roles -like "*Cloud Application Administrator*" -or $User.Roles -like "*Cloud App Admin*"
        $hasAppDev = $User.Roles -like "*Application Developer*" -or $User.Roles -like "*App Developer*"
        
        if ($hasAppAdmin) {
            $appRisks += "Application Administrator role"
            $appScore -= 25
        }
        
        if ($hasCloudAppAdmin) {
            $appRisks += "Cloud Application Administrator role"
            $appScore -= 20
        }
        
        if ($hasAppDev) {
            $appRisks += "Application Developer role"
            $appScore -= 15
        }
        
        # Check for dangerous combinations
        if ($hasAppAdmin -and $hasCloudAppAdmin) {
            $appRisks += "Multiple app admin roles"
            $appScore -= 10
        }
    }
    
    # Check for service accounts with app permissions (high risk)
    if ($User.UserName -like "*svc*" -or $User.UserName -like "*service*" -or $User.UserName -like "*app*") {
        if ($User.Roles -like "*Application*" -or $User.Roles -like "*App*") {
            $appRisks += "Service account with app permissions"
            $appScore -= 30
        }
    }
    
    # Check for guest accounts with app permissions (high risk)
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") {
        if ($User.Roles -like "*Application*" -or $User.Roles -like "*App*") {
            $appRisks += "Guest account with app permissions"
            $appScore -= 35
        }
    }
    
    # Check for users without MFA who have app permissions
    if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
        if ($User.Roles -like "*Application*" -or $User.Roles -like "*App*") {
            $appRisks += "No MFA on app permission account"
            $appScore -= 20
        }
    }
    
    # Check for inactive users with app permissions
    if ($User.TimeStamp -ne [DateTime]::MinValue) {
        $lastActivity = (Get-Date) - [DateTime]$User.TimeStamp
        if ($lastActivity.Days -gt 90 -and ($User.Roles -like "*Application*" -or $User.Roles -like "*App*")) {
            $appRisks += "Inactive user with app permissions"
            $appScore -= 15
        }
    }
    
    return @{
        Score = [Math]::Max(0, $appScore)
        Risks = $appRisks -join ", "
        HasRisks = $appRisks.Count -gt 0
    }
}

# Function to analyze device compliance
function Get-DeviceComplianceAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $deviceRisks = @()
    $deviceScore = 100
    
    # This is a simplified analysis - in reality you'd query Microsoft Graph for actual device compliance
    # For now, we'll analyze based on available data and common patterns
    
    # Check for users without MFA (device compliance often requires MFA)
    if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
        $deviceRisks += "No MFA (device compliance risk)"
        $deviceScore -= 25
    }
    
    # Check for guest users (often have device compliance issues)
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") {
        $deviceRisks += "Guest user (device compliance risk)"
        $deviceScore -= 20
    }
    
    # Check for service accounts (may not have device compliance)
    if ($User.UserName -like "*svc*" -or $User.UserName -like "*service*" -or $User.UserName -like "*app*") {
        $deviceRisks += "Service account (device compliance risk)"
        $deviceScore -= 15
    }
    
    # Check for inactive users (may have outdated device compliance)
    if ($User.TimeStamp -ne [DateTime]::MinValue) {
        $lastActivity = (Get-Date) - [DateTime]$User.TimeStamp
        if ($lastActivity.Days -gt 90) {
            $deviceRisks += "Inactive user (device compliance risk)"
            $deviceScore -= 10
        }
    }
    
    return @{
        Score = [Math]::Max(0, $deviceScore)
        Risks = $deviceRisks -join ", "
        HasRisks = $deviceRisks.Count -gt 0
    }
}

# Function to analyze conditional access
function Get-ConditionalAccessAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $caRisks = @()
    $caScore = 100
    
    # This is a simplified analysis - in reality you'd query Microsoft Graph for actual CA policies
    # For now, we'll analyze based on available data and common patterns
    
    # Check for users without MFA (CA often requires MFA)
    if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
        $caRisks += "No MFA (CA policy risk)"
        $caScore -= 30
    }
    
    # Check for guest users (often have CA policy issues)
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") {
        $caRisks += "Guest user (CA policy risk)"
        $caScore -= 25
    }
    
    # Check for privileged users without MFA (high CA risk)
    if ($User.UserRights -like "*Administrator*" -or $User.UserRights -like "*Admin*") {
        if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
            $caRisks += "Privileged user without MFA (CA risk)"
            $caScore -= 35
        }
    }
    
    # Check for service accounts (may not have CA policies)
    if ($User.UserName -like "*svc*" -or $User.UserName -like "*service*" -or $User.UserName -like "*app*") {
        $caRisks += "Service account (CA policy risk)"
        $caScore -= 20
    }
    
    return @{
        Score = [Math]::Max(0, $caScore)
        Risks = $caRisks -join ", "
        HasRisks = $caRisks.Count -gt 0
    }
}

# Function to analyze risky sign-ins
function Get-RiskySigninsAnalysis {
    param(
        [PSCustomObject]$User
    )
    
    $riskyRisks = @()
    $riskyScore = 100
    
    # This is a simplified analysis - in reality you'd query Microsoft Graph Identity Protection
    # For now, we'll analyze based on available data and common patterns
    
    # Check for users without MFA (higher risk of risky sign-ins)
    if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
        $riskyRisks += "No MFA (risky sign-in risk)"
        $riskyScore -= 25
    }
    
    # Check for guest users (often have risky sign-ins)
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") {
        $riskyRisks += "Guest user (risky sign-in risk)"
        $riskyScore -= 20
    }
    
    # Check for privileged users without MFA (high risky sign-in risk)
    if ($User.UserRights -like "*Administrator*" -or $User.UserRights -like "*Admin*") {
        if ($User.MFAStatus -eq "No Methods Registered" -or $User.MFAStatus -eq "Unknown") {
            $riskyRisks += "Privileged user without MFA (risky sign-in risk)"
            $riskyScore -= 35
        }
    }
    
    # Check for inactive users (may have risky sign-ins when they return)
    if ($User.TimeStamp -ne [DateTime]::MinValue) {
        $lastActivity = (Get-Date) - [DateTime]$User.TimeStamp
        if ($lastActivity.Days -gt 180) {
            $riskyRisks += "Inactive user (risky sign-in risk)"
            $riskyScore -= 15
        }
    }
    
    return @{
        Score = [Math]::Max(0, $riskyScore)
        Risks = $riskyRisks -join ", "
        HasRisks = $riskyRisks.Count -gt 0
    }
}

# Function to display help
function Show-Help {
    Write-Host "`n=== User Login History Script - Help ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "DESCRIPTION:" -ForegroundColor Yellow
    Write-Host "  Retrieves user login timestamps from local computer Windows Event Log,"
    Write-Host "  Active Directory, and/or Entra ID (Azure AD) sign-in logs."
    Write-Host "  Displays timestamps in human-readable format using the computer's local timezone."
    Write-Host ""
    Write-Host "PARAMETERS:" -ForegroundColor Yellow
    Write-Host "  -UserName <string>      : Filter by specific username (optional)"
    Write-Host "  -MaxRecords <int>       : Number of records to retrieve (default: 10, max: 1000)"
    Write-Host "  -ComputerName <string>  : Computer to query (default: local computer)"
    Write-Host "  -IncludeLocal           : Include local computer login logs"
    Write-Host "  -IncludeAD              : Include Active Directory login logs"
    Write-Host "  -IncludeEntraID         : Include Entra ID (Azure AD) login logs"
    Write-Host "  -ListUsers              : List all users with most recent login info"
    Write-Host "  -IncludePIN             : With -ListUsers, include WHfB (PIN) registration and last WHfB sign-in"
    Write-Host "  -Minimal                : Show minimal info when listing users (User, Rights, MFA, Roles, Login)"
    Write-Host "  -OutGridView            : Display ListUsers output in a GUI grid window"
    Write-Host "  -ExportExcel            : Export results to an Excel file (requires ImportExcel)"
    Write-Host "  -ExcelPath <path>       : Target Excel file path"
    Write-Host "  -ExcelWorksheet <name>  : Worksheet name to export to"
    Write-Host "  -IncludeRiskScore       : Include security risk scoring for users"
    Write-Host "  -IncludePrivilegedAccounts : Identify and flag privileged accounts with risk indicators"
    Write-Host "  -IncludeServiceAccounts : Detect and analyze service accounts (non-interactive, application accounts)"
    Write-Host "  -IncludeGuestUsers      : Identify and analyze guest users with access expiration dates"
    Write-Host "  -IncludePasswordPolicy  : Check password policy compliance (age, complexity, history)"
    Write-Host "  -IncludeAccountLockout  : Analyze account lockout events and failed login attempts"
    Write-Host "  -IncludeDeviceCompliance: Add device compliance status for Entra ID (managed, compliant, etc.)"
    Write-Host "  -IncludeConditionalAccess: Add Conditional Access policy analysis for Entra ID users"
    Write-Host "  -IncludeRiskySignins    : Integrate Microsoft Graph Identity Protection risky sign-ins"
    Write-Host "  -IncludeGroupMembership : Analyze group memberships and nested group relationships"
    Write-Host "  -IncludeAppPermissions  : Audit application permissions and consent grants"
    Write-Host "  -IncludeExportFormats   : Add multiple export formats (CSV, JSON, HTML, XML)"
    Write-Host "  -ConfigFile <path>      : Load configuration from JSON file"
    Write-Host "  -Profile <name>         : Use predefined profile (Quick, Standard, Comprehensive, Executive, Compliance)"
    Write-Host "  -Help                   : Display this help message"
    Write-Host ""
    Write-Host "ADVANCED FILTERING:" -ForegroundColor Yellow
    Write-Host "  -FilterByDepartment <string>   : Filter users by department"
    Write-Host "  -FilterByLocation <string>     : Filter users by office location"
    Write-Host "  -FilterByJobTitle <string>     : Filter users by job title"
    Write-Host "  -LastLoginAfter <datetime>     : Filter users who logged in after this date"
    Write-Host "  -LastLoginBefore <datetime>    : Filter users who logged in before this date"
    Write-Host "  -FilterByRiskLevel <string>    : Filter by risk level (Critical, High, Medium, Low, Minimal)"
    Write-Host "  -ShowOnlyNoMFA                 : Show only users without MFA"
    Write-Host "  -ShowOnlyPrivileged            : Show only privileged accounts"
    Write-Host "  -ShowOnlyDisabled              : Show only disabled accounts"
    Write-Host "  -ShowOnlyGuests                : Show only guest users"
    Write-Host "  -InactiveDays <int>            : Show only inactive accounts (no login in X days)"
    Write-Host ""
    Write-Host "CACHING:" -ForegroundColor Yellow
    Write-Host "  -UseCache                      : Use cached data if available"
    Write-Host "  -CacheExpiryMinutes <int>      : Cache expiry time in minutes (default: 60)"
    Write-Host "  -ClearCache                    : Clear cache before running"
    Write-Host ""
    Write-Host "COMPLIANCE REPORTING:" -ForegroundColor Yellow
    Write-Host "  -ComplianceFramework <string[]>: Generate compliance report for specific framework(s)"
    Write-Host "                                   Options: SOX, HIPAA, GDPR, PCI-DSS, ISO27001, NIST, CIS, All"
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\users.ps1"
    Write-Host "    Shows this help menu"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeLocal -MaxRecords 20"
    Write-Host "    Retrieves the last 20 login records from local computer"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeAD -UserName 'jdoe' -MaxRecords 5"
    Write-Host "    Retrieves the last 5 Active Directory login records for user"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -UserName 'jdoe@contoso.com' -MaxRecords 5"
    Write-Host "    Retrieves the last 5 Entra ID login records for user"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeLocal -IncludeAD -IncludeEntraID -MaxRecords 10"
    Write-Host "    Retrieves login records from local computer, AD, and Entra ID"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers"
    Write-Host "    Lists all users from Entra ID with their most recent login information"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -MaxRecords 50"
    Write-Host "    Lists first 50 users from Entra ID (faster for large directories)"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -Verbose"
    Write-Host "    Use -Verbose to see detailed processing information for troubleshooting"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludePIN"
    Write-Host "    Adds WHfB registration status and last WHfB sign-in per user"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludePIN -OutGridView"
    Write-Host "    Opens a GUI grid with WHfB fields visible (best for wide data)"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludePIN -ExportExcel -ExcelPath .\Users_List.xlsx"
    Write-Host "    Exports the users list to an Excel file"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore"
    Write-Host "    Shows users with security risk scoring (Critical/High/Medium/Low/Minimal)"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludePrivilegedAccounts"
    Write-Host "    Identifies and flags privileged accounts with risk indicators"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeServiceAccounts"
    Write-Host "    Detects and analyzes service accounts and application accounts"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeGuestUsers"
    Write-Host "    Identifies and analyzes guest users with access expiration dates"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludePasswordPolicy"
    Write-Host "    Checks password policy compliance (age, complexity, history)"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeAccountLockout"
    Write-Host "    Analyzes account lockout events and failed login attempts"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeDeviceCompliance"
    Write-Host "    Adds device compliance status for Entra ID (managed, compliant, etc.)"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeConditionalAccess"
    Write-Host "    Adds Conditional Access policy analysis for Entra ID users"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskySignins"
    Write-Host "    Integrates Microsoft Graph Identity Protection risky sign-ins"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeGroupMembership"
    Write-Host "    Analyzes group memberships and nested group relationships"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeAppPermissions"
    Write-Host "    Audits application permissions and consent grants"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -IncludeExportFormats -ExportExcel"
    Write-Host "    Exports to multiple formats (Excel, CSV, JSON, HTML, XML)"
    Write-Host ""
    Write-Host "  .\users.ps1 -Profile Comprehensive"
    Write-Host "    Runs comprehensive security audit with all analysis features"
    Write-Host ""
    Write-Host "  .\users.ps1 -Profile Executive -ExportExcel"
    Write-Host "    Generates executive summary with Excel export"
    Write-Host ""
    Write-Host "  .\users.ps1 -ConfigFile .\myconfig.json"
    Write-Host "    Loads custom configuration from JSON file"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -Minimal"
    Write-Host "    Shows minimal user information (User, Rights, MFA, Roles, Last Login)"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeAD -ListUsers -Minimal"
    Write-Host "    Shows minimal Active Directory user information"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -FilterByDepartment 'IT' -ShowOnlyNoMFA"
    Write-Host "    Shows IT department users who don't have MFA enabled"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -InactiveDays 90"
    Write-Host "    Shows users who haven't logged in for 90+ days"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -UseCache -CacheExpiryMinutes 30"
    Write-Host "    Uses cached data if available and less than 30 minutes old (improves performance)"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework 'SOX','HIPAA'"
    Write-Host "    Generates SOX and HIPAA compliance reports"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework 'All'"
    Write-Host "    Generates compliance reports for all frameworks (SOX, HIPAA, GDPR, PCI-DSS, ISO27001, NIST, CIS)"
    Write-Host ""
    Write-Host "REQUIREMENTS:" -ForegroundColor Yellow
    Write-Host "  Local Logs:"
    Write-Host "    - Administrator privileges required to read Security event log"
    Write-Host "    - Run PowerShell as Administrator"
    Write-Host "  Active Directory Logs:"
    Write-Host "    - ActiveDirectory PowerShell module"
    Write-Host "    - Install with: Install-WindowsFeature RSAT-AD-PowerShell"
    Write-Host "    - Or on Windows 10/11: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    Write-Host "  Entra ID Logs:"
    Write-Host "    - Microsoft.Graph PowerShell modules"
    Write-Host "    - Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    Write-Host "    - Requires: AuditLog.Read.All, Directory.Read.All, User.Read.All,"
    Write-Host "      and UserAuthenticationMethod.Read.All permissions"
    Write-Host ""
}

# Handle configuration and profiles
if ($ConfigFile) {
    $config = Get-Configuration -ConfigPath $ConfigFile
    if ($config) {
        # Apply configuration settings
        if ($config.MaxRecords) { $MaxRecords = $config.MaxRecords }
        if ($config.IncludeSources) {
            if ($config.IncludeSources.Local) { $IncludeLocal = $true }
            if ($config.IncludeSources.ActiveDirectory) { $IncludeAD = $true }
            if ($config.IncludeSources.EntraID) { $IncludeEntraID = $true }
        }
        if ($config.AnalysisFeatures) {
            if ($config.AnalysisFeatures.RiskScore) { $IncludeRiskScore = $true }
            if ($config.AnalysisFeatures.PrivilegedAccounts) { $IncludePrivilegedAccounts = $true }
            if ($config.AnalysisFeatures.ServiceAccounts) { $IncludeServiceAccounts = $true }
            if ($config.AnalysisFeatures.GuestUsers) { $IncludeGuestUsers = $true }
            if ($config.AnalysisFeatures.PasswordPolicy) { $IncludePasswordPolicy = $true }
            if ($config.AnalysisFeatures.AccountLockout) { $IncludeAccountLockout = $true }
            if ($config.AnalysisFeatures.GroupMembership) { $IncludeGroupMembership = $true }
            if ($config.AnalysisFeatures.AppPermissions) { $IncludeAppPermissions = $true }
            if ($config.AnalysisFeatures.DeviceCompliance) { $IncludeDeviceCompliance = $true }
            if ($config.AnalysisFeatures.ConditionalAccess) { $IncludeConditionalAccess = $true }
            if ($config.AnalysisFeatures.RiskySignins) { $IncludeRiskySignins = $true }
        }
        if ($config.ExportOptions) {
            if ($config.ExportOptions.Excel) { $ExportExcel = $true }
            if ($config.ExportOptions.MultipleFormats) { $IncludeExportFormats = $true }
        }
        if ($config.DisplayOptions) {
            if ($config.DisplayOptions.Minimal) { $Minimal = $true }
            if ($config.DisplayOptions.OutGridView) { $OutGridView = $true }
        }
    }
}

if ($Profile) {
    Set-ConfigurationProfile -ProfileName $Profile
}

# Check if no meaningful parameters were provided (show help by default)
if ($Help -or 
    (-not $PSBoundParameters.ContainsKey('UserName') -and 
     -not $PSBoundParameters.ContainsKey('MaxRecords') -and 
     -not $PSBoundParameters.ContainsKey('ComputerName') -and
     -not $IncludeLocal -and
     -not $IncludeAD -and
     -not $IncludeEntraID -and
     -not $ListUsers -and
     -not $Minimal -and
     -not $IncludeRiskScore -and
     -not $IncludePrivilegedAccounts -and
     -not $IncludeServiceAccounts -and
     -not $IncludeGuestUsers -and
     -not $IncludePasswordPolicy -and
     -not $IncludeAccountLockout -and
     -not $IncludeDeviceCompliance -and
     -not $IncludeConditionalAccess -and
     -not $IncludeRiskySignins -and
     -not $IncludeGroupMembership -and
     -not $IncludeAppPermissions -and
     -not $IncludeExportFormats -and
     -not $ConfigFile -and
     -not $Profile)) {
    Show-Help
    exit 0
}

# If no source is specified, default to Local
if (-not $IncludeLocal -and -not $IncludeAD -and -not $IncludeEntraID) {
    $IncludeLocal = $true
}

# Check for administrator privileges (only required for local logs)
if ($IncludeLocal -and -not (Test-Administrator)) {
    Write-Host "`n" -NoNewline
    Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
    Write-Host "Administrator privileges are required to access the local Security event log."
    Write-Host ""
    Write-Host "Please right-click PowerShell and select 'Run as Administrator', then try again." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Function to get user login timestamps
function Get-UserLoginHistory {
    param(
        [string]$User,
        [int]$Max,
        [string]$Computer
    )
    
    Write-Verbose "Querying login history on $Computer..."
    
    try {
        # Query Security log for successful logon events (Event ID 4624)
        # LogonType 2 = Interactive (local logon)
        # LogonType 10 = RemoteInteractive (RDP)
        # LogonType 11 = CachedInteractive
        
        $filterHashtable = @{
            LogName = 'Security'
            Id = 4624
        }
        
        if ($Computer -ne $env:COMPUTERNAME) {
            $filterHashtable.Add('ComputerName', $Computer)
        }
        
        Write-Verbose "Retrieving events from Security log..."
        $events = Get-WinEvent -FilterHashtable $filterHashtable -MaxEvents ($Max * 10) -ErrorAction Stop
        
        $loginEvents = @()
        
        foreach ($logonEvent in $events) {
            # Parse the event XML to extract user information
            $eventXml = [xml]$logonEvent.ToXml()
            $eventData = $eventXml.Event.EventData.Data
            
            # Extract relevant fields
            $targetUserName = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            $targetDomain = ($eventData | Where-Object {$_.Name -eq 'TargetDomainName'}).'#text'
            $logonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'
            $ipAddress = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
            $workstationName = ($eventData | Where-Object {$_.Name -eq 'WorkstationName'}).'#text'
            
            # Filter for interactive logons (2, 10, 11) and exclude system accounts
            if ($logonType -in @('2', '10', '11') -and 
                $targetUserName -notlike '*$' -and 
                $targetUserName -ne 'SYSTEM' -and 
                $targetUserName -ne 'LOCAL SERVICE' -and 
                $targetUserName -ne 'NETWORK SERVICE') {
                
                # Filter by username if specified
                if ($User -and $targetUserName -ne $User) {
                    continue
                }
                
                $logonTypeDescription = switch ($logonType) {
                    '2'  { 'Interactive' }
                    '10' { 'RemoteInteractive (RDP)' }
                    '11' { 'CachedInteractive' }
                    default { "Type $logonType" }
                }
                
                
                # Get user rights, MFA status, and PIN last set for local users
                $userRights = "Unknown"
                $mfaStatus = "Unknown"
                $mfaEnforcement = "Unknown"
                $pinLastSet = $null
                
                if ($targetDomain -eq $env:COMPUTERNAME -or $targetDomain -eq "WORKGROUP" -or $targetDomain -eq "") {
                    $userRights = Get-LocalUserRights -UserName $targetUserName
                    $mfaStatus = Get-LocalUserMFAStatus -UserName $targetUserName
                    $mfaEnforcement = "Not Applicable"
                    $pinLastSet = Get-LocalUserPINLastSet -UserName $targetUserName
                } else {
                    $userRights = "Domain User"
                    $mfaStatus = "Domain Managed"
                    $mfaEnforcement = "Domain Policy"
                    $pinLastSet = $null
                }
                
                $loginEvents += [PSCustomObject]@{
                    TimeStamp = $logonEvent.TimeCreated
                    UserName = $targetUserName
                    Domain = $targetDomain
                    LogonType = $logonTypeDescription
                    IPAddress = $ipAddress
                    Workstation = $workstationName
                    Computer = $Computer
                    Roles = "-"
                    UserRights = $userRights
                    MFAStatus = $mfaStatus
                    MFAEnforcement = $mfaEnforcement
                    PINLastSet = $pinLastSet
                    PasswordLastSet = $null
                }
                
                if ($loginEvents.Count -ge $Max) {
                    break
                }
            }
        }
        
        return $loginEvents
        
    } catch {
        # Silently handle errors - admin check is done earlier
        Write-Verbose "Failed to retrieve login events: $($_.Exception.Message)"
        return $null
    }
}

# Function to list Entra ID users
function Get-EntraIDUsersList {
    param(
        [string]$User,
        [int]$Max,
        [switch]$IncludePIN
    )
    
    Write-Verbose "Retrieving Entra ID users..."
    
    try {
        # Check if Microsoft.Graph modules are installed
        $requiredModules = @('Microsoft.Graph.Users', 'Microsoft.Graph.Authentication')
        if ($IncludePIN) {
            $requiredModules += 'Microsoft.Graph.Identity.SignIns'
        }
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
                Write-Host "$module module is not installed."
                Write-Host "To install, run: Install-Module $module -Scope CurrentUser" -ForegroundColor Cyan
                Write-Host ""
                return $null
            }
        }
        
        # Import required modules
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        if ($IncludePIN) { Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue }
        
        # Check if connected to Microsoft Graph
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
            Write-Host "Please authenticate in the browser window..." -ForegroundColor Gray
            
            try {
                Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "UserAuthenticationMethod.Read.All", "Device.Read.All" -ErrorAction Stop | Out-Null
            } catch {
                Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Yellow
                return $null
            }
        } else {
            Write-Verbose "Already connected to Microsoft Graph as: $($context.Account)"
        }
        
        Write-Verbose "Querying Entra ID users with sign-in activity..."
        
        # Get users with all properties in ONE call (much faster!)
        $mgUsers = @()
        $propertiesToSelect = @('Id','UserPrincipalName','DisplayName','Mail','AccountEnabled','CreatedDateTime','SignInActivity','LastPasswordChangeDateTime','SecurityIdentifier')
        
        if ($User) {
            $mgUsers = Get-MgUser -Filter "startsWith(userPrincipalName, '$User') or startsWith(displayName, '$User')" -Top $Max -ConsistencyLevel eventual -Property $propertiesToSelect
        } else {
            if ($Max -gt 0) {
                $mgUsers = Get-MgUser -Top $Max -ConsistencyLevel eventual -Property $propertiesToSelect
            } else {
                $mgUsers = Get-MgUser -All -ConsistencyLevel eventual -Property $propertiesToSelect
            }
        }
        
        Write-OperationStatus "Found $($mgUsers.Count) Entra ID users" "Success"
        
        $userList = @()
        $userCount = 0
        $totalUsers = $mgUsers.Count
        
        foreach ($mgUser in $mgUsers) {
            $userCount++
            Show-ProgressWithTiming -Activity "Processing Entra ID Users" -Status "Analyzing user" -Current $userCount -Total $totalUsers -CurrentItem $mgUser.UserPrincipalName
            Write-Verbose "Processing user $userCount of $($mgUsers.Count): $($mgUser.UserPrincipalName)"
            
            # Process user data
            $lastSignIn = $null
            $signInType = "-"
            
            if ($mgUser.SignInActivity) {
                if ($mgUser.SignInActivity.LastSignInDateTime) {
                    $lastSignIn = $mgUser.SignInActivity.LastSignInDateTime
                    $signInType = "Interactive"
                } elseif ($mgUser.SignInActivity.LastNonInteractiveSignInDateTime) {
                    $lastSignIn = $mgUser.SignInActivity.LastNonInteractiveSignInDateTime
                    $signInType = "Non-Interactive"
                }
            }
            
            # Get user's directory roles
            $userRoles = @()
            try {
                $memberOf = Get-MgUserMemberOf -UserId $mgUser.Id -ErrorAction SilentlyContinue
                foreach ($membership in $memberOf) {
                    if ($membership.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole') {
                        $userRoles += $membership.AdditionalProperties.displayName
                    }
                }
            } catch {
                Write-Verbose "Could not retrieve roles for user: $($mgUser.UserPrincipalName)"
            }
            
            $rolesString = if ($userRoles.Count -gt 0) { $userRoles -join ', ' } else { "-" }
            
            
            # Determine user rights based on roles
            $userRights = "Standard User"
            if ($rolesString -ne "-" -and $rolesString) {
                if ($rolesString -like "*Global Administrator*" -or $rolesString -like "*Global Admin*") {
                    $userRights = "Global Administrator"
                } elseif ($rolesString -like "*Administrator*" -or $rolesString -like "*Admin*") {
                    $userRights = "Administrator"
                } elseif ($rolesString -like "*User Administrator*" -or $rolesString -like "*User Admin*") {
                    $userRights = "User Administrator"
                } elseif ($rolesString -like "*Privileged*" -or $rolesString -like "*Privilege*") {
                    $userRights = "Privileged User"
                } else {
                    $userRights = "Custom Role: $rolesString"
                }
            }
            
            # Get MFA status, enforcement, and PIN last set for Entra ID users
            $mfaStatus = "Unknown"
            $mfaEnforcement = "Unknown"
            $pinLastSet = $null
            $hasWHfB = $false
            try {
                Write-Verbose "Checking MFA status for user: $($mgUser.UserPrincipalName)"
                
                # Check if user has MFA enabled
                $mfaMethods = Get-MgUserAuthenticationMethod -UserId $mgUser.Id -ErrorAction SilentlyContinue
                if ($mfaMethods) {
                    $mfaMethodTypes = @()
                    $windowsHelloMethod = $null
                    
                    foreach ($method in $mfaMethods) {
                        if ($method.AdditionalProperties.'@odata.type') {
                            $methodType = $method.AdditionalProperties.'@odata.type'
                            switch ($methodType) {
                                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { $mfaMethodTypes += "Authenticator App" }
                                '#microsoft.graph.phoneAuthenticationMethod' { $mfaMethodTypes += "Phone" }
                                '#microsoft.graph.emailAuthenticationMethod' { $mfaMethodTypes += "Email" }
                                '#microsoft.graph.fido2AuthenticationMethod' { $mfaMethodTypes += "FIDO2" }
                                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' { 
                                    $mfaMethodTypes += "Windows Hello"
                                    $windowsHelloMethod = $method
                                    $hasWHfB = $true
                                }
                                '#microsoft.graph.temporaryAccessPassAuthenticationMethod' { $mfaMethodTypes += "Temporary Access Pass" }
                                default { $mfaMethodTypes += "Other" }
                            }
                        }
                    }
                    
                    if ($mfaMethodTypes.Count -gt 0) {
                        $mfaStatus = ($mfaMethodTypes -join ", ")
                    } else {
                        $mfaStatus = "No Methods Registered"
                    }
                    
                    if ($IncludePIN) {
                    # Get PIN last set date from Windows Hello for Business method
                    if ($windowsHelloMethod) {
                        try {
                            if ($windowsHelloMethod.AdditionalProperties.createdDateTime) {
                                $pinLastSet = [DateTime]$windowsHelloMethod.AdditionalProperties.createdDateTime
                            } elseif ($windowsHelloMethod.AdditionalProperties.lastModifiedDateTime) {
                                $pinLastSet = [DateTime]$windowsHelloMethod.AdditionalProperties.lastModifiedDateTime
                            }
                            Write-Verbose "Windows Hello PIN last set: $pinLastSet"
                        } catch {
                            Write-Verbose "Could not parse Windows Hello PIN date: $($_.Exception.Message)"
                        }
                        }

                    }
                } else {
                    $mfaStatus = "No Methods Registered"
                }
                
                # Check MFA enforcement status
                # This is a simplified check - in reality you'd check Conditional Access policies
                if ($mfaStatus -ne "No Methods Registered" -and $mfaStatus -ne "Unknown") {
                    $mfaEnforcement = "Enabled"
                } else {
                    $mfaEnforcement = "Not Enforced"
                }
                
                Write-Verbose "MFA Status: $mfaStatus, Enforcement: $mfaEnforcement, PIN Last Set: $pinLastSet"
                
            } catch {
                Write-Verbose "Could not retrieve MFA information for user: $($mgUser.UserPrincipalName) - $($_.Exception.Message)"
                $mfaStatus = "Error Retrieving"
                $mfaEnforcement = "Unknown"
                $pinLastSet = $null
            }
            
            $userObj = [PSCustomObject]@{
                TimeStamp = if ($lastSignIn) { [DateTime]$lastSignIn } else { [DateTime]::MinValue }
                UserName = $mgUser.UserPrincipalName
                DisplayName = $mgUser.DisplayName
                Mail = $mgUser.Mail
                Roles = $rolesString
                UserRights = $userRights
                MFAStatus = $mfaStatus
                MFAEnforcement = $mfaEnforcement
                PINLastSet = $pinLastSet
                WHfBRegistered = $hasWHfB
                AppDisplayName = $signInType
                Status = if ($mgUser.AccountEnabled) { "Enabled" } else { "Disabled" }
                Enabled = $mgUser.AccountEnabled
                PasswordLastSet = $mgUser.LastPasswordChangeDateTime
                CreatedDate = $mgUser.CreatedDateTime
                Source = "Entra ID"
            }
            
            # Add risk scoring if requested
            if ($IncludeRiskScore) {
                $riskData = Get-SecurityRiskScore -User $userObj
                $userObj | Add-Member -NotePropertyName "RiskScore" -NotePropertyValue $riskData.Score -Force
                $userObj | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue $riskData.Level -Force
                $userObj | Add-Member -NotePropertyName "RiskFactors" -NotePropertyValue $riskData.Factors -Force
            }
            
            # Add privileged account analysis if requested
            if ($IncludePrivilegedAccounts) {
                $privilegeData = Get-PrivilegedAccountAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "PrivilegeLevel" -NotePropertyValue $privilegeData.Level -Force
                $userObj | Add-Member -NotePropertyName "PrivilegeRisks" -NotePropertyValue $privilegeData.Risks -Force
                $userObj | Add-Member -NotePropertyName "IsPrivileged" -NotePropertyValue $privilegeData.IsPrivileged -Force
            }
            
            # Add service account analysis if requested
            if ($IncludeServiceAccounts) {
                $serviceData = Get-ServiceAccountAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "AccountType" -NotePropertyValue $serviceData.Type -Force
                $userObj | Add-Member -NotePropertyName "ServiceRisks" -NotePropertyValue $serviceData.Risks -Force
                $userObj | Add-Member -NotePropertyName "IsServiceAccount" -NotePropertyValue $serviceData.IsServiceAccount -Force
            }
            
            # Add guest user analysis if requested
            if ($IncludeGuestUsers) {
                $guestData = Get-GuestUserAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "GuestStatus" -NotePropertyValue $guestData.Status -Force
                $userObj | Add-Member -NotePropertyName "GuestRisks" -NotePropertyValue $guestData.Risks -Force
                $userObj | Add-Member -NotePropertyName "IsGuestUser" -NotePropertyValue $guestData.IsGuestUser -Force
                $userObj | Add-Member -NotePropertyName "AccessExpiration" -NotePropertyValue $guestData.AccessExpiration -Force
            }
            
            # Add password policy analysis if requested
            if ($IncludePasswordPolicy) {
                $passwordData = Get-PasswordPolicyAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "PasswordPolicyScore" -NotePropertyValue $passwordData.Score -Force
                $userObj | Add-Member -NotePropertyName "PasswordPolicyLevel" -NotePropertyValue $passwordData.Level -Force
                $userObj | Add-Member -NotePropertyName "PasswordViolations" -NotePropertyValue $passwordData.Violations -Force
                $userObj | Add-Member -NotePropertyName "HasPasswordViolations" -NotePropertyValue $passwordData.HasViolations -Force
            }
            
            # Add account lockout analysis if requested
            if ($IncludeAccountLockout) {
                $lockoutData = Get-AccountLockoutAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "LockoutScore" -NotePropertyValue $lockoutData.Score -Force
                $userObj | Add-Member -NotePropertyName "LockoutRisks" -NotePropertyValue $lockoutData.Risks -Force
                $userObj | Add-Member -NotePropertyName "HasLockoutRisks" -NotePropertyValue $lockoutData.HasRisks -Force
            }
            
            # Add group membership analysis if requested
            if ($IncludeGroupMembership) {
                $groupData = Get-GroupMembershipAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "GroupScore" -NotePropertyValue $groupData.Score -Force
                $userObj | Add-Member -NotePropertyName "GroupRisks" -NotePropertyValue $groupData.Risks -Force
                $userObj | Add-Member -NotePropertyName "HasGroupRisks" -NotePropertyValue $groupData.HasRisks -Force
            }
            
            # Add application permissions analysis if requested
            if ($IncludeAppPermissions) {
                $appData = Get-AppPermissionsAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "AppScore" -NotePropertyValue $appData.Score -Force
                $userObj | Add-Member -NotePropertyName "AppRisks" -NotePropertyValue $appData.Risks -Force
                $userObj | Add-Member -NotePropertyName "HasAppRisks" -NotePropertyValue $appData.HasRisks -Force
            }
            
            # Add device compliance analysis if requested
            if ($IncludeDeviceCompliance) {
                $deviceData = Get-DeviceComplianceAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "DeviceScore" -NotePropertyValue $deviceData.Score -Force
                $userObj | Add-Member -NotePropertyName "DeviceRisks" -NotePropertyValue $deviceData.Risks -Force
                $userObj | Add-Member -NotePropertyName "HasDeviceRisks" -NotePropertyValue $deviceData.HasRisks -Force
            }
            
            # Add conditional access analysis if requested
            if ($IncludeConditionalAccess) {
                $caData = Get-ConditionalAccessAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "CAScore" -NotePropertyValue $caData.Score -Force
                $userObj | Add-Member -NotePropertyName "CARisks" -NotePropertyValue $caData.Risks -Force
                $userObj | Add-Member -NotePropertyName "HasCARisks" -NotePropertyValue $caData.HasRisks -Force
            }
            
            # Add risky sign-ins analysis if requested
            if ($IncludeRiskySignins) {
                $riskyData = Get-RiskySigninsAnalysis -User $userObj
                $userObj | Add-Member -NotePropertyName "RiskyScore" -NotePropertyValue $riskyData.Score -Force
                $userObj | Add-Member -NotePropertyName "RiskyRisks" -NotePropertyValue $riskyData.Risks -Force
                $userObj | Add-Member -NotePropertyName "HasRiskyRisks" -NotePropertyValue $riskyData.HasRisks -Force
            }
            
            $userList += $userObj
        }
        
        Write-Progress -Activity "Processing Entra ID Users" -Completed
        Write-OperationStatus "Completed processing $($userList.Count) users" "Success"
        
        return $userList
        
    } catch {
        Write-Verbose "Failed to retrieve Entra ID users: $($_.Exception.Message)"
        Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to retrieve Entra ID users."
        
        # Check if it's a throttling error
        if ($_.Exception.Message -like "*throttled*" -or $_.Exception.Message -like "*429*") {
            Write-Host "Microsoft Graph API rate limit reached. Please wait a few minutes and try again." -ForegroundColor Yellow
        } else {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Gray
        }
        return $null
    }
}

# Function to get Entra ID login history
function Get-EntraIDLoginHistory {
    param(
        [string]$User,
        [int]$Max
    )
    
    Write-Verbose "Querying Entra ID login history..."
    
    try {
        # Check if Microsoft.Graph modules are installed
        $requiredModules = @('Microsoft.Graph.Reports', 'Microsoft.Graph.Authentication')
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
                Write-Host "$module module is not installed."
                Write-Host "To install, run: Install-Module $module -Scope CurrentUser" -ForegroundColor Cyan
                Write-Host ""
                return $null
            }
        }
        
        # Import required modules
        Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        
        # Check if connected to Microsoft Graph
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
            Write-Host "Please authenticate in the browser window..." -ForegroundColor Gray
            
            try {
                Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -ErrorAction Stop | Out-Null
            } catch {
                Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Yellow
                return $null
            }
        } else {
            Write-Verbose "Already connected to Microsoft Graph as: $($context.Account)"
        }
        
        $loginEvents = @()
        
        # Get recent sign-in logs
        Write-Verbose "Retrieving sign-in logs from Entra ID..."
        
        # Build filter for Microsoft Graph query
        $filter = ""
        if ($User) {
            $filter = "userPrincipalName eq '$User' or startsWith(userPrincipalName, '$User')"
        }
        
        # Query sign-in logs
        $signInLogs = @()
        if ($filter) {
            $signInLogs = Get-MgAuditLogSignIn -Filter $filter -Top $Max -ErrorAction Stop
        } else {
            $signInLogs = Get-MgAuditLogSignIn -Top $Max -ErrorAction Stop
        }
        
        foreach ($log in $signInLogs) {
            # Convert status to success/failure
            $status = if ($log.Status.ErrorCode -eq 0) { "Success" } else { "Failed" }
            
            # Only include successful logins
            if ($status -eq "Success") {
                $loginEvents += [PSCustomObject]@{
                    TimeStamp = $log.CreatedDateTime.ToLocalTime()
                    UserName = $log.UserPrincipalName
                    DisplayName = $log.UserDisplayName
                    AppDisplayName = $log.AppDisplayName
                    IPAddress = $log.IPAddress
                    Location = "$($log.Location.City), $($log.Location.CountryOrRegion)"
                    DeviceDetail = $log.DeviceDetail.OperatingSystem
                    Status = $status
                    Roles = "-"
                    UserRights = "Entra ID User"
                    MFAStatus = "Unknown"
                    MFAEnforcement = "Unknown"
                    PINLastSet = $null
                    PasswordLastSet = $null
                    Source = "Entra ID"
                }
            }
            
            if ($loginEvents.Count -ge $Max) {
                break
            }
        }
        
        return $loginEvents
        
    } catch {
        Write-Verbose "Failed to retrieve Entra ID login events: $($_.Exception.Message)"
        Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to retrieve Entra ID logs. Ensure you have the required permissions."
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Gray
        return $null
    }
}

# Function to get Active Directory login history
function Get-ADLoginHistory {
    param(
        [string]$User,
        [int]$Max
    )
    
    Write-Verbose "Querying Active Directory login history..."
    
    try {
        # Check if ActiveDirectory module is installed
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "ActiveDirectory PowerShell module is not installed."
            Write-Host "To install on Windows Server: Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Cyan
            Write-Host "To install on Windows 10/11: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Cyan
            Write-Host ""
            return $null
        }
        
        # Import ActiveDirectory module
        Import-Module ActiveDirectory -ErrorAction Stop
        
        Write-Verbose "Retrieving user information from Active Directory..."
        
        # Build filter for AD query
        $filter = "*"
        if ($User) {
            $filter = "SamAccountName -eq '$User' -or UserPrincipalName -eq '$User' -or Name -like '*$User*'"
        }
        
        # Get all domain controllers for accurate LastLogon info
        $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        
        # Query AD users
        $adUsers = Get-ADUser -Filter $filter -Properties LastLogonDate, LastLogon, PasswordLastSet, Enabled, Description, MemberOf -ErrorAction Stop
        
        if (-not $adUsers) {
            Write-Verbose "No users found matching the criteria"
            return @()
        }
        
        $loginEvents = @()
        
        foreach ($adUser in $adUsers) {
            # Get the most recent LastLogon across all DCs (not replicated)
            $lastLogon = $null
            $lastLogonDC = ""
            
            foreach ($dc in $domainControllers) {
                try {
                    $userOnDC = Get-ADUser $adUser.SamAccountName -Server $dc -Properties LastLogon -ErrorAction SilentlyContinue
                    if ($userOnDC.LastLogon -and ($null -eq $lastLogon -or $userOnDC.LastLogon -gt $lastLogon)) {
                        $lastLogon = $userOnDC.LastLogon
                        $lastLogonDC = $dc
                    }
                } catch {
                    Write-Verbose "Could not query DC: $dc"
                }
            }
            
            # Convert LastLogon from FileTime to DateTime
            $lastLogonDate = $null
            if ($lastLogon -and $lastLogon -ne 0) {
                $lastLogonDate = [DateTime]::FromFileTime($lastLogon)
            } elseif ($adUser.LastLogonDate) {
                # Fall back to LastLogonDate (replicated but less accurate)
                $lastLogonDate = $adUser.LastLogonDate
            }
            
            # Get user's group memberships (limit to first 5 for display)
            $userGroups = @()
            if ($adUser.MemberOf) {
                foreach ($groupDN in $adUser.MemberOf | Select-Object -First 5) {
                    # Extract CN from DN (e.g., "CN=Domain Admins,CN=Users,DC=domain,DC=com" -> "Domain Admins")
                    if ($groupDN -match '^CN=([^,]+)') {
                        $userGroups += $matches[1]
                    }
                }
            }
            $groupsString = if ($userGroups.Count -gt 0) { 
                $groupsString = $userGroups -join ', '
                if ($adUser.MemberOf.Count -gt 5) {
                    $groupsString += " (+$($adUser.MemberOf.Count - 5) more)"
                }
                $groupsString
            } else { 
                "-" 
            }
            
            # Determine user rights based on AD groups
            $userRights = "Standard User"
            if ($groupsString -ne "-" -and $groupsString) {
                if ($groupsString -like "*Domain Admins*" -or $groupsString -like "*Enterprise Admins*") {
                    $userRights = "Domain Administrator"
                } elseif ($groupsString -like "*Administrators*" -or $groupsString -like "*Admin*") {
                    $userRights = "Administrator"
                } elseif ($groupsString -like "*Power Users*") {
                    $userRights = "Power User"
                } elseif ($groupsString -like "*Backup Operators*" -or $groupsString -like "*Backup*") {
                    $userRights = "Backup Operator"
                } elseif ($groupsString -like "*Remote Desktop Users*" -or $groupsString -like "*RDP*") {
                    $userRights = "Remote Desktop User"
                } elseif ($groupsString -like "*Privileged*" -or $groupsString -like "*Privilege*") {
                    $userRights = "Privileged User"
                } else {
                    $userRights = "Custom Groups: $($userGroups -join ', ')"
                }
            }
            
            # Determine MFA status and PIN last set for AD users
            $mfaStatus = "Unknown"
            $mfaEnforcement = "Unknown"
            $pinLastSet = $null
            try {
                # For AD users, MFA is typically managed through:
                # 1. Windows Hello for Business (if configured)
                # 2. Smart card authentication
                # 3. Third-party MFA solutions
                # 4. Azure AD Connect with MFA
                
                # Check if user has smart card authentication enabled
                if ($adUser.'msDS-KeyCredentialLink' -and $adUser.'msDS-KeyCredentialLink'.Count -gt 0) {
                    $mfaStatus = "Windows Hello/Smart Card"
                    $mfaEnforcement = "AD Policy"
                    
                    # Try to get PIN last set from msDS-KeyCredentialLink
                    # This is a simplified approach - the actual date would need to be parsed from the binary data
                    try {
                        # For now, we'll use the user's last password change as a proxy
                        # In reality, you'd need to parse the msDS-KeyCredentialLink binary data
                        if ($adUser.PasswordLastSet) {
                            $pinLastSet = $adUser.PasswordLastSet
                        }
                        Write-Verbose "Windows Hello/Smart Card configured for $($adUser.SamAccountName)"
                    } catch {
                        Write-Verbose "Could not determine PIN last set for $($adUser.SamAccountName): $($_.Exception.Message)"
                    }
                } else {
                    # Check if user is in any MFA-related groups
                    $mfaGroups = @("MFA Users", "Smart Card Users", "Certificate Users")
                    $hasMfaGroup = $false
                    foreach ($group in $mfaGroups) {
                        if ($groupsString -like "*$group*") {
                            $mfaStatus = "Group-Based MFA"
                            $mfaEnforcement = "AD Policy"
                            $hasMfaGroup = $true
                            break
                        }
                    }
                    
                    if (-not $hasMfaGroup) {
                        $mfaStatus = "Password Only"
                        $mfaEnforcement = "Not Enforced"
                    }
                }
                
            } catch {
                Write-Verbose "Could not determine MFA status for AD user: $($adUser.SamAccountName) - $($_.Exception.Message)"
                $mfaStatus = "Unknown"
                $mfaEnforcement = "Unknown"
                $pinLastSet = $null
            }
            
            
            # Only add users with a login date
            if ($lastLogonDate) {
                $loginEvents += [PSCustomObject]@{
                    TimeStamp = $lastLogonDate
                    UserName = $adUser.SamAccountName
                    UserPrincipalName = $adUser.UserPrincipalName
                    DisplayName = $adUser.Name
                    Roles = $groupsString
                    UserRights = $userRights
                    MFAStatus = $mfaStatus
                    MFAEnforcement = $mfaEnforcement
                    PINLastSet = $pinLastSet
                    Enabled = $adUser.Enabled
                    DomainController = $lastLogonDC
                    PasswordLastSet = $adUser.PasswordLastSet
                    Description = $adUser.Description
                    Source = "Active Directory"
                }
            }
        }
        
        # Sort by most recent login and limit to MaxRecords
        $loginEvents = $loginEvents | Sort-Object TimeStamp -Descending | Select-Object -First $Max
        
        return $loginEvents
        
    } catch {
        Write-Verbose "Failed to retrieve Active Directory login events: $($_.Exception.Message)"
        Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
        Write-Host "Failed to retrieve Active Directory logs. Ensure the AD module is installed and you have permissions."
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Gray
        return $null
    }
}

# Main execution
Write-Host "`n=== User Login History ===" -ForegroundColor Cyan

# Determine sources
$sources = @()
if ($IncludeLocal) { $sources += "Local Computer" }
if ($IncludeAD) { $sources += "Active Directory" }
if ($IncludeEntraID) { $sources += "Entra ID" }
Write-Host "Sources: $($sources -join ', ')" -ForegroundColor Gray

if ($IncludeLocal) {
    Write-Host "Computer: $ComputerName" -ForegroundColor Gray
}
Write-Host "Timezone: $((Get-TimeZone).DisplayName)" -ForegroundColor Gray
if ($UserName) {
    Write-Host "User Filter: $UserName" -ForegroundColor Gray
}
Write-Host "Max Records: $MaxRecords (per source)" -ForegroundColor Gray
Write-Host ""

$allLoginHistory = @()

# Retrieve local login history
if ($IncludeLocal) {
    if ($ListUsers) {
        Write-Host "Retrieving local users from login history..." -ForegroundColor Cyan
        $localHistory = Get-UserLoginHistory -User $UserName -Max 1000 -Computer $ComputerName
        
        if ($localHistory -and $localHistory.Count -gt 0) {
            # Group by username and get unique users with their most recent login
            $uniqueUsers = $localHistory | Group-Object UserName
            
            foreach ($userGroup in $uniqueUsers) {
                # Get most recent login
                $mostRecentLogin = $userGroup.Group | Sort-Object TimeStamp -Descending | Select-Object -First 1
                
                
                # Get user rights, MFA status, and PIN last set for local user
                $userRights = Get-LocalUserRights -UserName $userGroup.Name
                $mfaStatus = Get-LocalUserMFAStatus -UserName $userGroup.Name
                $mfaEnforcement = "Not Applicable"
                $pinLastSet = Get-LocalUserPINLastSet -UserName $userGroup.Name
                
                # Create user object
                $userObj = [PSCustomObject]@{
                    TimeStamp = $mostRecentLogin.TimeStamp
                    UserName = $userGroup.Name
                    DisplayName = $userGroup.Name
                    Mail = "-"
                    Roles = "-"
                    UserRights = $userRights
                    MFAStatus = $mfaStatus
                    MFAEnforcement = $mfaEnforcement
                    PINLastSet = $pinLastSet
                    AppDisplayName = "Local Logon"
                    Status = "Unknown"
                    Enabled = $null
                    PasswordLastSet = $null
                    CreatedDate = $null
                    Source = "Local"
                }
                $allLoginHistory += $userObj
            }
            
            Write-Host "  Found $($uniqueUsers.Count) local user(s)" -ForegroundColor Green
        } else {
            Write-Host "  No local login records found" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Retrieving local computer login logs..." -ForegroundColor Cyan
        $localHistory = Get-UserLoginHistory -User $UserName -Max $MaxRecords -Computer $ComputerName
        
        if ($localHistory -and $localHistory.Count -gt 0) {
            # Add source identifier
            foreach ($record in $localHistory) {
                $record | Add-Member -NotePropertyName "Source" -NotePropertyValue "Local" -Force
            }
            $allLoginHistory += $localHistory
            Write-Host "  Found $($localHistory.Count) local login record(s)" -ForegroundColor Green
        } else {
            Write-Host "  No local login records found" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# Retrieve Active Directory login history
if ($IncludeAD) {
    Write-Host "Retrieving Active Directory login logs..." -ForegroundColor Cyan
    # AD always lists users by default (shows last logon per user)
    $adHistory = Get-ADLoginHistory -User $UserName -Max $MaxRecords
    
    if ($adHistory -and $adHistory.Count -gt 0) {
        $allLoginHistory += $adHistory
        Write-Host "  Found $($adHistory.Count) Active Directory login record(s)" -ForegroundColor Green
    } else {
        Write-Host "  No Active Directory login records found or module not available" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Retrieve Entra ID data
if ($IncludeEntraID) {
    if ($ListUsers) {
        Write-Host "Retrieving Entra ID users..." -ForegroundColor Cyan
        $entraIDHistory = Get-EntraIDUsersList -User $UserName -Max $MaxRecords -IncludePIN:$IncludePIN
    } else {
        Write-Host "Retrieving Entra ID login logs..." -ForegroundColor Cyan
        $entraIDHistory = Get-EntraIDLoginHistory -User $UserName -Max $MaxRecords
    }
    
    if ($entraIDHistory -and $entraIDHistory.Count -gt 0) {
        $allLoginHistory += $entraIDHistory
        if ($ListUsers) {
            Write-Host "  Found $($entraIDHistory.Count) Entra ID user(s)" -ForegroundColor Green
        } else {
            Write-Host "  Found $($entraIDHistory.Count) Entra ID login record(s)" -ForegroundColor Green
        }
    } else {
        if ($ListUsers) {
            Write-Host "  No Entra ID users found or module not available" -ForegroundColor Yellow
        } else {
            Write-Host "  No Entra ID login records found or module not available" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# Handle caching
if ($ClearCache) {
    Clear-AuditCache
}

# Try to load from cache if enabled
$cacheKey = "UserAudit_$($IncludeLocal)_$($IncludeAD)_$($IncludeEntraID)_$($ListUsers)"
if ($UseCache -and $allLoginHistory.Count -eq 0) {
    $cachedData = Get-FromCache -CacheKey $cacheKey -ExpiryMinutes $CacheExpiryMinutes
    if ($cachedData) {
        $allLoginHistory = $cachedData
        Write-OperationStatus "Using cached data ($($allLoginHistory.Count) records)" "Success"
    }
}

# Save to cache if enabled and we have fresh data
if ($UseCache -and $allLoginHistory.Count -gt 0 -and -not $cachedData) {
    Save-ToCache -CacheKey $cacheKey -Data $allLoginHistory
}

# Display combined results
if ($allLoginHistory.Count -gt 0) {
    # Apply advanced filters if specified
    $hasFilters = $FilterByDepartment -or $FilterByLocation -or $FilterByJobTitle -or $LastLoginAfter -or $LastLoginBefore -or $FilterByRiskLevel -or $ShowOnlyNoMFA -or $ShowOnlyPrivileged -or $ShowOnlyDisabled -or $ShowOnlyGuests -or ($InactiveDays -gt 0)
    
    if ($hasFilters) {
        $originalCount = $allLoginHistory.Count
        $allLoginHistory = Invoke-AdvancedFilters -UserData $allLoginHistory `
            -Department $FilterByDepartment `
            -Location $FilterByLocation `
            -JobTitle $FilterByJobTitle `
            -LoginAfter $LastLoginAfter `
            -LoginBefore $LastLoginBefore `
            -RiskLevel $FilterByRiskLevel `
            -OnlyNoMFA:$ShowOnlyNoMFA `
            -OnlyPrivileged:$ShowOnlyPrivileged `
            -OnlyDisabled:$ShowOnlyDisabled `
            -OnlyGuests:$ShowOnlyGuests `
            -InactiveDays $InactiveDays
        
        if ($allLoginHistory.Count -eq 0) {
            Write-Host "`n" + "="*70 -ForegroundColor Yellow
            Write-Host "NO RESULTS MATCH THE APPLIED FILTERS" -ForegroundColor Yellow
            Write-Host "="*70 -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Original record count: $originalCount" -ForegroundColor Gray
            Write-Host "Filtered record count: 0" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Try adjusting your filter criteria." -ForegroundColor Gray
            return
        }
    }
    
    Write-Host "=== Login Records (Total: $($allLoginHistory.Count)) ===" -ForegroundColor Cyan
    Write-Host ""
    
    # If ListUsers is specified, sort by username; otherwise sort by timestamp
    if ($ListUsers) {
        # Sort alphabetically by username for user listings
        $allLoginHistory = $allLoginHistory | Sort-Object UserName
        
        Write-Host ""
        Write-Host "=== Users List (Total: $($allLoginHistory.Count)) ===" -ForegroundColor Cyan
        Write-Host ""
        
        # Display users directly (data is already per-user from source functions)
        if ($OutGridView) {
            $allLoginHistory | Out-GridView -Title "Users List"
            if ($ExportExcel) { $exportData = $allLoginHistory }
            # Don't return early if compliance framework is requested
            elseif (-not $ComplianceFramework) { Write-Host ""; return }
        }
        
        # Custom colored display for risk scores
        if ($IncludeRiskScore) {
            Write-Host "`n=== Users with Risk Scoring ===" -ForegroundColor Cyan
            Write-Host ""
            
            foreach ($user in $allLoginHistory) {
                # Display user info with colored risk indicators
                Write-Host "User: " -NoNewline -ForegroundColor White
                Write-Host $user.UserName -ForegroundColor Cyan
                
                Write-Host "  Display Name: " -NoNewline -ForegroundColor Gray
                Write-Host $user.DisplayName -ForegroundColor White
                
                Write-Host "  User Rights: " -NoNewline -ForegroundColor Gray
                Write-Host $user.UserRights -ForegroundColor White
                
                Write-Host "  MFA Status: " -NoNewline -ForegroundColor Gray
                Write-Host $user.MFAStatus -ForegroundColor White
                
                if ($user.PSObject.Properties.Name -contains 'RiskScore') {
                    $scoreColor = Get-RiskScoreColor -Score $user.RiskScore
                    $levelColor = Get-RiskLevelColor -Level $user.RiskLevel
                    
                    Write-Host "  Risk Score: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.RiskScore -ForegroundColor $scoreColor
                    
                    Write-Host "  Risk Level: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.RiskLevel -ForegroundColor $levelColor
                    
                    if ($user.PSObject.Properties.Name -contains 'RiskFactors' -and $user.RiskFactors) {
                        Write-Host "  Risk Factors: " -NoNewline -ForegroundColor Gray
                        Write-Host $user.RiskFactors -ForegroundColor Yellow
                    }
                }
                
                if ($user.PSObject.Properties.Name -contains 'PrivilegeLevel' -and $user.PrivilegeLevel -ne "Standard") {
                    Write-Host "  Privilege Level: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.PrivilegeLevel -ForegroundColor Red
                }
                
                if ($user.PSObject.Properties.Name -contains 'IsServiceAccount' -and $user.IsServiceAccount) {
                    Write-Host "  Account Type: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.AccountType -ForegroundColor Magenta
                }
                
                if ($user.PSObject.Properties.Name -contains 'IsGuestUser' -and $user.IsGuestUser) {
                    Write-Host "  Guest Status: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.GuestStatus -ForegroundColor Cyan
                }
                
                if ($user.PSObject.Properties.Name -contains 'PasswordPolicyScore') {
                    $passwordScoreColor = Get-PasswordScoreColor -Score $user.PasswordPolicyScore
                    $passwordLevelColor = Get-PasswordLevelColor -Level $user.PasswordPolicyLevel
                    
                    Write-Host "  Password Score: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.PasswordPolicyScore -ForegroundColor $passwordScoreColor
                    
                    Write-Host "  Password Level: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.PasswordPolicyLevel -ForegroundColor $passwordLevelColor
                    
                    if ($user.PSObject.Properties.Name -contains 'PasswordViolations' -and $user.PasswordViolations) {
                        Write-Host "  Password Issues: " -NoNewline -ForegroundColor Gray
                        Write-Host $user.PasswordViolations -ForegroundColor Yellow
                    }
                }
                
                if ($user.PSObject.Properties.Name -contains 'LockoutScore') {
                    $lockoutScoreColor = Get-LockoutScoreColor -Score $user.LockoutScore
                    
                    Write-Host "  Lockout Score: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.LockoutScore -ForegroundColor $lockoutScoreColor
                    
                    if ($user.PSObject.Properties.Name -contains 'LockoutRisks' -and $user.LockoutRisks) {
                        Write-Host "  Lockout Risks: " -NoNewline -ForegroundColor Gray
                        Write-Host $user.LockoutRisks -ForegroundColor Yellow
                    }
                }
                
                if ($user.PSObject.Properties.Name -contains 'AppScore') {
                    $appScoreColor = Get-LockoutScoreColor -Score $user.AppScore  # Reuse lockout color function
                    
                    Write-Host "  App Score: " -NoNewline -ForegroundColor Gray
                    Write-Host $user.AppScore -ForegroundColor $appScoreColor
                    
                    if ($user.PSObject.Properties.Name -contains 'AppRisks' -and $user.AppRisks) {
                        Write-Host "  App Risks: " -NoNewline -ForegroundColor Gray
                        Write-Host $user.AppRisks -ForegroundColor Yellow
                    }
                }
                
                Write-Host "  Last Login: " -NoNewline -ForegroundColor Gray
                if ($user.TimeStamp -eq [DateTime]::MinValue) {
                    Write-Host "Never" -ForegroundColor Red
                } else {
                    Write-Host $user.TimeStamp.ToString('yyyy-MM-dd HH:mm') -ForegroundColor White
                }
                
                Write-Host ""
            }
            
            if ($ExportExcel) { $exportData = $allLoginHistory }
            Write-Host ""
            # Don't return early if compliance framework is requested
            if (-not $ExportExcel -and -not $ComplianceFramework) { return }
        }
        
        if ($Minimal) {
            # Minimal view - always include basic columns plus any requested analysis columns
            $columns = @(
                @{Label='User'; Width=28; Expression={$_.UserName}},
                @{Label='Display Name'; Width=24; Expression={$_.DisplayName}},
                @{Label='User Rights'; Width=18; Expression={if ($_.UserRights) { $_.UserRights } else { "-" }}},
                @{Label='MFA Status'; Width=16; Expression={if ($_.MFAStatus) { $_.MFAStatus } else { "-" }}},
                @{Label='MFA Enforcement'; Width=16; Expression={if ($_.MFAEnforcement) { $_.MFAEnforcement } else { "-" }}},
                @{Label='Status'; Width=8; Expression={$_.Status}},
                @{Label='Last Login'; Width=19; Expression={
                    if ($_.TimeStamp -eq [DateTime]::MinValue) { 
                        "Never" 
                    } else { 
                        $_.TimeStamp.ToString('yyyy-MM-dd HH:mm') 
                    }
                }}
            )
            
            # Add requested analysis columns
            if ($IncludePIN) {
                $columns += @{Label='WHfB Registered'; Width=6; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'WHfBRegistered') { if ($_.WHfBRegistered) { 'Yes' } else { 'No' } } else { '-' } }}
            }
            if ($IncludeRiskScore) {
                $columns += @{Label='Risk Score'; Width=10; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'RiskScore') { $_.RiskScore } else { '-' } }}
                $columns += @{Label='Risk Level'; Width=10; Expression={ if ($_.PSObject.Properties.Name -contains 'RiskLevel') { $_.RiskLevel } else { '-' } }}
            }
            if ($IncludePrivilegedAccounts) {
                $columns += @{Label='Privilege Level'; Width=18; Expression={ if ($_.PSObject.Properties.Name -contains 'PrivilegeLevel') { $_.PrivilegeLevel } else { '-' } }}
            }
            if ($IncludeServiceAccounts) {
                $columns += @{Label='Account Type'; Width=18; Expression={ if ($_.PSObject.Properties.Name -contains 'AccountType') { $_.AccountType } else { '-' } }}
            }
            if ($IncludeGuestUsers) {
                $columns += @{Label='Guest Status'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'GuestStatus') { $_.GuestStatus } else { '-' } }}
            }
            if ($IncludePasswordPolicy) {
                $columns += @{Label='Password Score'; Width=12; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'PasswordPolicyScore') { $_.PasswordPolicyScore } else { '-' } }}
            }
            if ($IncludeAccountLockout) {
                $columns += @{Label='Lockout Score'; Width=12; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'LockoutScore') { $_.LockoutScore } else { '-' } }}
            }
            if ($IncludeAppPermissions) {
                $columns += @{Label='App Score'; Width=9; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'AppScore') { $_.AppScore } else { '-' } }}
            }
            if ($IncludeGroupMembership) {
                $columns += @{Label='Group Score'; Width=10; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'GroupScore') { $_.GroupScore } else { '-' } }}
            }
            if ($IncludeDeviceCompliance) {
                $columns += @{Label='Device Score'; Width=11; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'DeviceScore') { $_.DeviceScore } else { '-' } }}
            }
            if ($IncludeConditionalAccess) {
                $columns += @{Label='CA Score'; Width=8; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'CAScore') { $_.CAScore } else { '-' } }}
            }
            if ($IncludeRiskySignins) {
                $columns += @{Label='Risky Score'; Width=11; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'RiskyScore') { $_.RiskyScore } else { '-' } }}
            }
            
            # Always include roles at the end
            $columns += @{Label='Roles'; Width=32; Expression={if ($_.Roles) { $_.Roles } else { "-" }}}
            
            $formatted = $allLoginHistory | Format-Table -Property $columns -Wrap
            if ($ExportExcel) { $exportData = $allLoginHistory } else { $formatted }
                    } else { 
            # Extended view - always show full set plus WHfB fields (when available)
            $columns = @(
                @{Label='User'; Width=28; Expression={$_.UserName}},
                @{Label='Display Name'; Width=24; Expression={$_.DisplayName}},
                @{Label='Email'; Width=26; Expression={if ($_.Mail) { $_.Mail } else { "-" }}},
                @{Label='User Rights'; Width=18; Expression={if ($_.UserRights) { $_.UserRights } else { "-" }}},
                @{Label='MFA Status'; Width=16; Expression={if ($_.MFAStatus) { $_.MFAStatus } else { "-" }}},
                @{Label='MFA Enforcement'; Width=16; Expression={if ($_.MFAEnforcement) { $_.MFAEnforcement } else { "-" }}}
            )
            if ($IncludePIN) {
                $columns += @(
                    @{Label='WHfB Registered'; Width=6; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'WHfBRegistered') { if ($_.WHfBRegistered) { 'Yes' } else { 'No' } } else { '-' } }}
                )
            }
            if ($IncludeRiskScore) {
                $columns += @(
                    @{Label='Risk Score'; Width=10; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'RiskScore') { $_.RiskScore } else { '-' } }},
                    @{Label='Risk Level'; Width=10; Expression={ if ($_.PSObject.Properties.Name -contains 'RiskLevel') { $_.RiskLevel } else { '-' } }}
                )
            }
            if ($IncludePrivilegedAccounts) {
                $columns += @(
                    @{Label='Privilege Level'; Width=18; Expression={ if ($_.PSObject.Properties.Name -contains 'PrivilegeLevel') { $_.PrivilegeLevel } else { '-' } }},
                    @{Label='Is Privileged'; Width=12; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'IsPrivileged') { if ($_.IsPrivileged) { 'Yes' } else { 'No' } } else { '-' } }}
                )
            }
            if ($IncludeServiceAccounts) {
                $columns += @(
                    @{Label='Account Type'; Width=18; Expression={ if ($_.PSObject.Properties.Name -contains 'AccountType') { $_.AccountType } else { '-' } }},
                    @{Label='Is Service'; Width=10; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'IsServiceAccount') { if ($_.IsServiceAccount) { 'Yes' } else { 'No' } } else { '-' } }}
                )
            }
            if ($IncludeGuestUsers) {
                $columns += @(
                    @{Label='Guest Status'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'GuestStatus') { $_.GuestStatus } else { '-' } }},
                    @{Label='Is Guest'; Width=8; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'IsGuestUser') { if ($_.IsGuestUser) { 'Yes' } else { 'No' } } else { '-' } }}
                )
            }
            if ($IncludePasswordPolicy) {
                $columns += @(
                    @{Label='Password Policy'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'PasswordPolicyLevel') { $_.PasswordPolicyLevel } else { '-' } }},
                    @{Label='Password Score'; Width=12; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'PasswordPolicyScore') { $_.PasswordPolicyScore } else { '-' } }}
                )
            }
            if ($IncludeAccountLockout) {
                $columns += @(
                    @{Label='Lockout Score'; Width=12; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'LockoutScore') { $_.LockoutScore } else { '-' } }},
                    @{Label='Lockout Risks'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'LockoutRisks') { $_.LockoutRisks } else { '-' } }}
                )
            }
            if ($IncludeGroupMembership) {
                $columns += @(
                    @{Label='Group Score'; Width=10; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'GroupScore') { $_.GroupScore } else { '-' } }},
                    @{Label='Group Risks'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'GroupRisks') { $_.GroupRisks } else { '-' } }}
                )
            }
            if ($IncludeAppPermissions) {
                $columns += @(
                    @{Label='App Score'; Width=9; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'AppScore') { $_.AppScore } else { '-' } }},
                    @{Label='App Risks'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'AppRisks') { $_.AppRisks } else { '-' } }}
                )
            }
            if ($IncludeDeviceCompliance) {
                $columns += @(
                    @{Label='Device Score'; Width=11; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'DeviceScore') { $_.DeviceScore } else { '-' } }},
                    @{Label='Device Risks'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'DeviceRisks') { $_.DeviceRisks } else { '-' } }}
                )
            }
            if ($IncludeConditionalAccess) {
                $columns += @(
                    @{Label='CA Score'; Width=8; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'CAScore') { $_.CAScore } else { '-' } }},
                    @{Label='CA Risks'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'CARisks') { $_.CARisks } else { '-' } }}
                )
            }
            if ($IncludeRiskySignins) {
                $columns += @(
                    @{Label='Risky Score'; Width=11; Alignment='Center'; Expression={ if ($_.PSObject.Properties.Name -contains 'RiskyScore') { $_.RiskyScore } else { '-' } }},
                    @{Label='Risky Risks'; Width=15; Expression={ if ($_.PSObject.Properties.Name -contains 'RiskyRisks') { $_.RiskyRisks } else { '-' } }}
                )
            }
            $columns += @(
                @{Label='Roles'; Width=32; Expression={if ($_.Roles) { $_.Roles } else { "-" }}},
                @{Label='Last Login'; Width=19; Expression={
                    if ($_.TimeStamp -eq [DateTime]::MinValue) { 
                        "Never" 
                    } else { 
                        $_.TimeStamp.ToString('yyyy-MM-dd HH:mm') 
                    }
                }},
                @{Label='Password Last Set'; Width=19; Expression={
                    if ($_.PasswordLastSet) { 
                        if ($_.PasswordLastSet -is [DateTime]) {
                            $_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm')
                        } else {
                            ([DateTime]$_.PasswordLastSet).ToString('yyyy-MM-dd HH:mm')
                        }
                    } else { 
                        "-" 
                    }
                }},
                @{Label='Login Type'; Width=16; Expression={
                    if ($_.AppDisplayName -and $_.AppDisplayName -ne '-') { $_.AppDisplayName }
                    elseif ($_.LogonType) { $_.LogonType }
                    else { "-" }
                }},
                @{Label='Status'; Width=9; Expression={$_.Status}},
                @{Label='Source'; Width=8; Expression={$_.Source}},
                @{Label='Computer/DC'; Width=16; Expression={
                    if ($_.Computer) { $_.Computer }
                    elseif ($_.DomainController) { $_.DomainController }
                    else { "-" }
                }},
                @{Label='Domain'; Width=12; Expression={if ($_.Domain) { $_.Domain } else { "-" }}},
                @{Label='Enabled'; Width=7; Expression={
                    if ($null -ne $_.Enabled) { $_.Enabled } else { "-" }
                }}
            )
            $formatted = $allLoginHistory | Format-Table -Property $columns -Wrap
            if ($ExportExcel) { $exportData = $allLoginHistory } else { $formatted }
        }
        
        if ($ExportExcel) { $exportData = $allLoginHistory }
        Write-Host ""
        # Don't return early if compliance framework is requested
        if (-not $ExportExcel -and -not $ComplianceFramework) { return }
    }
    
    # Sort login events by timestamp (most recent first)
    $allLoginHistory = $allLoginHistory | Sort-Object TimeStamp -Descending
    
    # Display results based on source
    $sourceCount = ($IncludeLocal -as [int]) + ($IncludeAD -as [int]) + ($IncludeEntraID -as [int])
    
    if ($sourceCount -eq 1) {
        # Single source - show source-specific columns
        if ($IncludeLocal) {
            # Local only
            $allLoginHistory | Format-Table -AutoSize -Property `
                @{Label='Login Time'; Expression={$_.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss')}},
                @{Label='Computer'; Expression={$_.Computer}},
                @{Label='User'; Expression={$_.UserName}},
                @{Label='User Rights'; Expression={if ($_.UserRights) { $_.UserRights } else { "-" }}},
                @{Label='MFA Status'; Expression={if ($_.MFAStatus) { $_.MFAStatus } else { "-" }}},
                @{Label='MFA Enforcement'; Expression={if ($_.MFAEnforcement) { $_.MFAEnforcement } else { "-" }}},
                
                @{Label='Domain'; Expression={$_.Domain}},
                @{Label='Logon Type'; Expression={$_.LogonType}},
                @{Label='IP Address'; Expression={if($_.IPAddress -and $_.IPAddress -ne '-') {$_.IPAddress} else {'Local'}}},
                @{Label='Workstation'; Expression={$_.Workstation}}
        } elseif ($IncludeAD) {
            # Active Directory only
            $allLoginHistory | Format-Table -AutoSize -Property `
                @{Label='Last Logon'; Expression={$_.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss')}},
                @{Label='User'; Expression={$_.UserName}},
                @{Label='User Rights'; Expression={if ($_.UserRights) { $_.UserRights } else { "-" }}},
                @{Label='MFA Status'; Expression={if ($_.MFAStatus) { $_.MFAStatus } else { "-" }}},
                @{Label='MFA Enforcement'; Expression={if ($_.MFAEnforcement) { $_.MFAEnforcement } else { "-" }}},
                
                @{Label='Display Name'; Expression={$_.DisplayName}},
                @{Label='UPN'; Expression={$_.UserPrincipalName}},
                @{Label='Enabled'; Expression={$_.Enabled}},
                @{Label='Domain Controller'; Expression={$_.DomainController}},
                @{Label='Password Last Set'; Expression={if($_.PasswordLastSet) {$_.PasswordLastSet.ToString('yyyy-MM-dd')} else {'Never'}}}
        } elseif ($IncludeEntraID) {
            # Entra ID only
            $allLoginHistory | Format-Table -AutoSize -Property `
                @{Label='Login Time'; Expression={$_.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss')}},
                @{Label='User'; Expression={$_.UserName}},
                @{Label='User Rights'; Expression={if ($_.UserRights) { $_.UserRights } else { "-" }}},
                @{Label='MFA Status'; Expression={if ($_.MFAStatus) { $_.MFAStatus } else { "-" }}},
                @{Label='MFA Enforcement'; Expression={if ($_.MFAEnforcement) { $_.MFAEnforcement } else { "-" }}},
                
                @{Label='Display Name'; Expression={$_.DisplayName}},
                @{Label='Application'; Expression={$_.AppDisplayName}},
                @{Label='IP Address'; Expression={$_.IPAddress}},
                @{Label='Location'; Expression={$_.Location}},
                @{Label='Device'; Expression={$_.DeviceDetail}}
        }
    } else {
        # Multiple sources - show combined view with source column
        $allLoginHistory | Format-Table -AutoSize -Property `
            @{Label='Login Time'; Expression={$_.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss')}},
            @{Label='Source'; Expression={
                if ($_.Source -eq "Active Directory") { "AD" }
                elseif ($_.Source -eq "Entra ID") { "Entra" }
                else { $_.Source }
            }},
            @{Label='User'; Expression={$_.UserName}},
            @{Label='User Rights'; Expression={if ($_.UserRights) { $_.UserRights } else { "-" }}},
            @{Label='MFA Status'; Expression={if ($_.MFAStatus) { $_.MFAStatus } else { "-" }}},
            @{Label='MFA Enforcement'; Expression={if ($_.MFAEnforcement) { $_.MFAEnforcement } else { "-" }}},
            
            @{Label='Computer/DC'; Expression={
                if ($_.Source -eq "Local") {
                    $_.Computer
                } elseif ($_.Source -eq "Active Directory") {
                    $_.DomainController
                } else {
                    "-"
                }
            }},
            @{Label='Application'; Expression={
                if ($_.Source -eq "Local") {
                    "$($_.Domain)\$($_.LogonType)"
                } elseif ($_.Source -eq "Active Directory") {
                    if ($_.Enabled) { "Enabled" } else { "Disabled" }
                } else {
                    $_.AppDisplayName
                }
            }},
            @{Label='IP Address'; Expression={
                if ($_.Source -eq "Local") {
                    if ($_.IPAddress -and $_.IPAddress -ne '-') { $_.IPAddress } else { 'Local' }
                } elseif ($_.Source -eq "Active Directory") {
                    "-"
                } else {
                    $_.IPAddress
                }
            }},
            @{Label='Device'; Expression={
                if ($_.Source -eq "Local") {
                    $_.Workstation
                } elseif ($_.Source -eq "Active Directory") {
                    $_.UserPrincipalName
                } else {
                    $_.DeviceDetail
                }
            }},
            @{Label='Location'; Expression={
                if ($_.Source -eq "Entra ID") {
                    $_.Location
                } else {
                    "-"
                }
            }}
    }
    
} else {
    Write-Host "No login records found matching the criteria." -ForegroundColor Yellow
}

# Generate Compliance Reports if requested
$complianceData = $null
if ($ComplianceFramework -and $ComplianceFramework.Count -gt 0 -and $allLoginHistory.Count -gt 0) {
    Write-Host ""
    # Get structured compliance data for export
    $complianceData = Get-ComplianceData -UserData $allLoginHistory -Frameworks $ComplianceFramework
    # Display compliance reports
    New-ComplianceReport -UserData $allLoginHistory -Frameworks $ComplianceFramework
    Write-Host ""
}

# Excel Export functionality
if ($ExportExcel -and $exportData -and $exportData.Count -gt 0) {
    try {
        # Check if ImportExcel module is available
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            Write-Host "`nWARNING: " -ForegroundColor Yellow -NoNewline
            Write-Host "ImportExcel module is not installed."
            Write-Host "To install, run: Install-Module ImportExcel -Scope CurrentUser" -ForegroundColor Cyan
            Write-Host "Falling back to CSV export..." -ForegroundColor Yellow
            
            # Fallback to CSV
            $csvPath = if ($ExcelPath) { $ExcelPath -replace '\.xlsx$', '.csv' } else { Join-Path $OutputDirectory "Users_Export.csv" }
            $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Data exported to CSV: $csvPath" -ForegroundColor Green
        } else {
            # Import the module
            Import-Module ImportExcel -ErrorAction SilentlyContinue
            
            # Set default paths if not provided
            if (-not $ExcelPath) {
                $ExcelPath = if ($ListUsers) { "Users_List.xlsx" } else { "Login_Records.xlsx" }
            }
            
            # Ensure ExcelPath includes the output directory
            if (-not [System.IO.Path]::IsPathRooted($ExcelPath)) {
                $ExcelPath = Join-Path $OutputDirectory $ExcelPath
            }
            
            # Set default worksheet name if not provided
            if (-not $ExcelWorksheet) {
                $ExcelWorksheet = if ($ListUsers) { "Users" } else { "Logins" }
            }
            
            # Prepare data for export (ensure all fields are included)
            $exportDataForExcel = $exportData | ForEach-Object {
                $row = [PSCustomObject]@{}
                
                # Copy all existing properties
                foreach ($prop in $_.PSObject.Properties) {
                    $value = $prop.Value
                    if ($value -is [DateTime] -and $value -ne [DateTime]::MinValue) {
                        $row | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $value.ToString('yyyy-MM-dd HH:mm:ss')
                    } else {
                        $row | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $value
                    }
                }
                
                # Ensure all analysis fields are included in Excel export
                # Risk Score fields
                if (-not $row.PSObject.Properties.Name -contains 'RiskScore') { $row | Add-Member -NotePropertyName "RiskScore" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'RiskLevel') { $row | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'RiskFactors') { $row | Add-Member -NotePropertyName "RiskFactors" -NotePropertyValue $null -Force }
                
                # Privileged Account fields
                if (-not $row.PSObject.Properties.Name -contains 'PrivilegeLevel') { $row | Add-Member -NotePropertyName "PrivilegeLevel" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'PrivilegeRisks') { $row | Add-Member -NotePropertyName "PrivilegeRisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'IsPrivileged') { $row | Add-Member -NotePropertyName "IsPrivileged" -NotePropertyValue $null -Force }
                
                # Service Account fields
                if (-not $row.PSObject.Properties.Name -contains 'AccountType') { $row | Add-Member -NotePropertyName "AccountType" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'ServiceRisks') { $row | Add-Member -NotePropertyName "ServiceRisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'IsServiceAccount') { $row | Add-Member -NotePropertyName "IsServiceAccount" -NotePropertyValue $null -Force }
                
                # Guest User fields
                if (-not $row.PSObject.Properties.Name -contains 'GuestStatus') { $row | Add-Member -NotePropertyName "GuestStatus" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'GuestRisks') { $row | Add-Member -NotePropertyName "GuestRisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'IsGuestUser') { $row | Add-Member -NotePropertyName "IsGuestUser" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'AccessExpiration') { $row | Add-Member -NotePropertyName "AccessExpiration" -NotePropertyValue $null -Force }
                
                # Password Policy fields
                if (-not $row.PSObject.Properties.Name -contains 'PasswordPolicyScore') { $row | Add-Member -NotePropertyName "PasswordPolicyScore" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'PasswordPolicyLevel') { $row | Add-Member -NotePropertyName "PasswordPolicyLevel" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'PasswordViolations') { $row | Add-Member -NotePropertyName "PasswordViolations" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'HasPasswordViolations') { $row | Add-Member -NotePropertyName "HasPasswordViolations" -NotePropertyValue $null -Force }
                
                # Account Lockout fields
                if (-not $row.PSObject.Properties.Name -contains 'LockoutScore') { $row | Add-Member -NotePropertyName "LockoutScore" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'LockoutRisks') { $row | Add-Member -NotePropertyName "LockoutRisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'HasLockoutRisks') { $row | Add-Member -NotePropertyName "HasLockoutRisks" -NotePropertyValue $null -Force }
                
                # Group Membership fields
                if (-not $row.PSObject.Properties.Name -contains 'GroupScore') { $row | Add-Member -NotePropertyName "GroupScore" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'GroupRisks') { $row | Add-Member -NotePropertyName "GroupRisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'HasGroupRisks') { $row | Add-Member -NotePropertyName "HasGroupRisks" -NotePropertyValue $null -Force }
                
                # Application Permissions fields
                if (-not $row.PSObject.Properties.Name -contains 'AppScore') { $row | Add-Member -NotePropertyName "AppScore" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'AppRisks') { $row | Add-Member -NotePropertyName "AppRisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'HasAppRisks') { $row | Add-Member -NotePropertyName "HasAppRisks" -NotePropertyValue $null -Force }
                
                # Device Compliance fields
                if (-not $row.PSObject.Properties.Name -contains 'DeviceScore') { $row | Add-Member -NotePropertyName "DeviceScore" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'DeviceRisks') { $row | Add-Member -NotePropertyName "DeviceRisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'HasDeviceRisks') { $row | Add-Member -NotePropertyName "HasDeviceRisks" -NotePropertyValue $null -Force }
                
                # Conditional Access fields
                if (-not $row.PSObject.Properties.Name -contains 'CAScore') { $row | Add-Member -NotePropertyName "CAScore" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'CARisks') { $row | Add-Member -NotePropertyName "CARisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'HasCARisks') { $row | Add-Member -NotePropertyName "HasCARisks" -NotePropertyValue $null -Force }
                
                # Risky Sign-ins fields
                if (-not $row.PSObject.Properties.Name -contains 'RiskyScore') { $row | Add-Member -NotePropertyName "RiskyScore" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'RiskyRisks') { $row | Add-Member -NotePropertyName "RiskyRisks" -NotePropertyValue $null -Force }
                if (-not $row.PSObject.Properties.Name -contains 'HasRiskyRisks') { $row | Add-Member -NotePropertyName "HasRiskyRisks" -NotePropertyValue $null -Force }
                
                # WHfB fields
                if (-not $row.PSObject.Properties.Name -contains 'WHfBRegistered') { $row | Add-Member -NotePropertyName "WHfBRegistered" -NotePropertyValue $null -Force }
                
                $row
            }
            
            # Export to Excel with formatting
            $exportDataForExcel | Export-Excel -Path $ExcelPath -WorksheetName $ExcelWorksheet -AutoSize -TableStyle Medium2 -FreezeTopRow -BoldTopRow
            
            # Export compliance data if available
            if ($complianceData -and $complianceData.Count -gt 0) {
                $complianceData | Export-Excel -Path $ExcelPath -WorksheetName "Compliance" -AutoSize -TableStyle Medium2 -FreezeTopRow -BoldTopRow
                Write-Host "Compliance data exported to worksheet: Compliance" -ForegroundColor Green
            }
            
            Write-Host "`nData exported to Excel: $ExcelPath" -ForegroundColor Green
            Write-Host "Worksheet: $ExcelWorksheet" -ForegroundColor Green
            Write-Host "Records exported: $($exportData.Count)" -ForegroundColor Green
        }
        
        # Multiple Export Formats if requested
        if ($IncludeExportFormats) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $baseName = if ($ListUsers) { "Users_List" } else { "Login_Records" }
            
            # Prepare data for export (format DateTime objects and ensure all fields are included)
            $exportDataForExport = $exportData | ForEach-Object {
                $obj = $_.PSObject.Copy()
                
                # Format all DateTime objects to strings for export compatibility
                if ($obj.TimeStamp -and $obj.TimeStamp -ne [DateTime]::MinValue) {
                    $obj.TimeStamp = $obj.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss')
                }
                if ($obj.PasswordLastSet -and $obj.PasswordLastSet -ne [DateTime]::MinValue) {
                    $obj.PasswordLastSet = $obj.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss')
                }
                if ($obj.CreatedDate -and $obj.CreatedDate -ne [DateTime]::MinValue) {
                    $obj.CreatedDate = $obj.CreatedDate.ToString('yyyy-MM-dd HH:mm:ss')
                }
                
                # Ensure all analysis fields are included in export
                # Risk Score fields
                if (-not $obj.PSObject.Properties.Name -contains 'RiskScore') { $obj | Add-Member -NotePropertyName "RiskScore" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'RiskLevel') { $obj | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'RiskFactors') { $obj | Add-Member -NotePropertyName "RiskFactors" -NotePropertyValue $null -Force }
                
                # Privileged Account fields
                if (-not $obj.PSObject.Properties.Name -contains 'PrivilegeLevel') { $obj | Add-Member -NotePropertyName "PrivilegeLevel" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'PrivilegeRisks') { $obj | Add-Member -NotePropertyName "PrivilegeRisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'IsPrivileged') { $obj | Add-Member -NotePropertyName "IsPrivileged" -NotePropertyValue $null -Force }
                
                # Service Account fields
                if (-not $obj.PSObject.Properties.Name -contains 'AccountType') { $obj | Add-Member -NotePropertyName "AccountType" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'ServiceRisks') { $obj | Add-Member -NotePropertyName "ServiceRisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'IsServiceAccount') { $obj | Add-Member -NotePropertyName "IsServiceAccount" -NotePropertyValue $null -Force }
                
                # Guest User fields
                if (-not $obj.PSObject.Properties.Name -contains 'GuestStatus') { $obj | Add-Member -NotePropertyName "GuestStatus" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'GuestRisks') { $obj | Add-Member -NotePropertyName "GuestRisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'IsGuestUser') { $obj | Add-Member -NotePropertyName "IsGuestUser" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'AccessExpiration') { $obj | Add-Member -NotePropertyName "AccessExpiration" -NotePropertyValue $null -Force }
                
                # Password Policy fields
                if (-not $obj.PSObject.Properties.Name -contains 'PasswordPolicyScore') { $obj | Add-Member -NotePropertyName "PasswordPolicyScore" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'PasswordPolicyLevel') { $obj | Add-Member -NotePropertyName "PasswordPolicyLevel" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'PasswordViolations') { $obj | Add-Member -NotePropertyName "PasswordViolations" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'HasPasswordViolations') { $obj | Add-Member -NotePropertyName "HasPasswordViolations" -NotePropertyValue $null -Force }
                
                # Account Lockout fields
                if (-not $obj.PSObject.Properties.Name -contains 'LockoutScore') { $obj | Add-Member -NotePropertyName "LockoutScore" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'LockoutRisks') { $obj | Add-Member -NotePropertyName "LockoutRisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'HasLockoutRisks') { $obj | Add-Member -NotePropertyName "HasLockoutRisks" -NotePropertyValue $null -Force }
                
                # Group Membership fields
                if (-not $obj.PSObject.Properties.Name -contains 'GroupScore') { $obj | Add-Member -NotePropertyName "GroupScore" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'GroupRisks') { $obj | Add-Member -NotePropertyName "GroupRisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'HasGroupRisks') { $obj | Add-Member -NotePropertyName "HasGroupRisks" -NotePropertyValue $null -Force }
                
                # Application Permissions fields
                if (-not $obj.PSObject.Properties.Name -contains 'AppScore') { $obj | Add-Member -NotePropertyName "AppScore" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'AppRisks') { $obj | Add-Member -NotePropertyName "AppRisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'HasAppRisks') { $obj | Add-Member -NotePropertyName "HasAppRisks" -NotePropertyValue $null -Force }
                
                # Device Compliance fields
                if (-not $obj.PSObject.Properties.Name -contains 'DeviceScore') { $obj | Add-Member -NotePropertyName "DeviceScore" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'DeviceRisks') { $obj | Add-Member -NotePropertyName "DeviceRisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'HasDeviceRisks') { $obj | Add-Member -NotePropertyName "HasDeviceRisks" -NotePropertyValue $null -Force }
                
                # Conditional Access fields
                if (-not $obj.PSObject.Properties.Name -contains 'CAScore') { $obj | Add-Member -NotePropertyName "CAScore" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'CARisks') { $obj | Add-Member -NotePropertyName "CARisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'HasCARisks') { $obj | Add-Member -NotePropertyName "HasCARisks" -NotePropertyValue $null -Force }
                
                # Risky Sign-ins fields
                if (-not $obj.PSObject.Properties.Name -contains 'RiskyScore') { $obj | Add-Member -NotePropertyName "RiskyScore" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'RiskyRisks') { $obj | Add-Member -NotePropertyName "RiskyRisks" -NotePropertyValue $null -Force }
                if (-not $obj.PSObject.Properties.Name -contains 'HasRiskyRisks') { $obj | Add-Member -NotePropertyName "HasRiskyRisks" -NotePropertyValue $null -Force }
                
                # WHfB fields
                if (-not $obj.PSObject.Properties.Name -contains 'WHfBRegistered') { $obj | Add-Member -NotePropertyName "WHfBRegistered" -NotePropertyValue $null -Force }
                
                $obj
            }
            
            # CSV Export
            $csvPath = Join-Path $OutputDirectory "${baseName}_${timestamp}.csv"
            $exportDataForExport | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Data exported to CSV: $csvPath" -ForegroundColor Green
            
            # Export compliance data to CSV if available
            if ($complianceData -and $complianceData.Count -gt 0) {
                $complianceCsvPath = Join-Path $OutputDirectory "${baseName}_Compliance_${timestamp}.csv"
                $complianceData | Export-Csv -Path $complianceCsvPath -NoTypeInformation -Encoding UTF8
                Write-Host "Compliance data exported to CSV: $complianceCsvPath" -ForegroundColor Green
            }
            
            # JSON Export
            $jsonData = @{
                UserData = $exportDataForExport
                ComplianceReports = $complianceData
                GeneratedAt = Get-Date
                TotalUsers = $exportDataForExport.Count
            }
            $jsonPath = Join-Path $OutputDirectory "${baseName}_${timestamp}.json"
            $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            Write-Host "Data exported to JSON: $jsonPath" -ForegroundColor Green
            
            # HTML Report Export
            $htmlPath = Join-Path $OutputDirectory "${baseName}_${timestamp}.html"
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>IT Security Audit Report - $baseName</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        .critical { background-color: #ffebee; }
        .high { background-color: #fff3e0; }
        .medium { background-color: #fffde7; }
        .low { background-color: #e8f5e8; }
        .minimal { background-color: #e3f2fd; }
    </style>
</head>
<body>
    <h1>IT Security Audit Report</h1>
    <h2>$baseName - Generated: $(Get-Date)</h2>
    <p>Total Records: $($exportData.Count)</p>
    <table>
        <thead>
            <tr>
"@
            
            # Add table headers
            if ($exportData.Count -gt 0) {
                $firstRecord = $exportData[0]
                foreach ($property in $firstRecord.PSObject.Properties.Name) {
                    $htmlContent += "<th>$property</th>`n"
                }
            }
            
            $htmlContent += @"
            </tr>
        </thead>
        <tbody>
"@
            
            # Add table rows
            foreach ($record in $exportDataForExport) {
                $rowClass = ""
                # Determine row color based on risk level or other analysis scores
                if ($record.PSObject.Properties.Name -contains 'RiskLevel') {
                    $rowClass = switch ($record.RiskLevel) {
                        "Critical" { "critical" }
                        "High" { "high" }
                        "Medium" { "medium" }
                        "Low" { "low" }
                        "Minimal" { "minimal" }
                        default { "" }
                    }
                } elseif ($record.PSObject.Properties.Name -contains 'PasswordPolicyLevel') {
                    $rowClass = switch ($record.PasswordPolicyLevel) {
                        "Critical" { "critical" }
                        "High Risk" { "high" }
                        "Non-Compliant" { "medium" }
                        "Minor Issues" { "low" }
                        "Compliant" { "minimal" }
                        default { "" }
                    }
                }
                
                $htmlContent += "<tr class='$rowClass'>`n"
                foreach ($property in $record.PSObject.Properties.Name) {
                    $value = $record.$property
                    if ($null -eq $value) { $value = "" }
                    $htmlContent += "<td>$value</td>`n"
                }
                $htmlContent += "</tr>`n"
            }
            
            $htmlContent += @"
        </tbody>
    </table>
"@
            
            # Add compliance section to HTML if available
            if ($complianceData -and $complianceData.Count -gt 0) {
                $htmlContent += @"
    
    <h2>Compliance Reports</h2>
    <p>Total Frameworks Analyzed: $($complianceData.Count)</p>
    <table>
        <thead>
            <tr>
"@
                # Add compliance table headers
                $firstCompliance = $complianceData[0]
                foreach ($property in $firstCompliance.PSObject.Properties.Name) {
                    $htmlContent += "<th>$property</th>`n"
                }
                
                $htmlContent += @"
            </tr>
        </thead>
        <tbody>
"@
                
                # Add compliance table rows
                foreach ($report in $complianceData) {
                    $rowClass = if ($report.OverallStatus -eq "PASS") { "minimal" } else { "high" }
                    $htmlContent += "<tr class='$rowClass'>`n"
                    foreach ($property in $report.PSObject.Properties.Name) {
                        $value = $report.$property
                        if ($null -eq $value) { $value = "" }
                        $htmlContent += "<td>$value</td>`n"
                    }
                    $htmlContent += "</tr>`n"
                }
                
                $htmlContent += @"
        </tbody>
    </table>
"@
            }
            
            $htmlContent += @"
</body>
</html>
"@
            
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
            Write-Host "Data exported to HTML: $htmlPath" -ForegroundColor Green
            
            # XML Export
            $xmlData = @{
                UserData = $exportDataForExport
                ComplianceReports = $complianceData
                GeneratedAt = Get-Date
                TotalUsers = $exportDataForExport.Count
            }
            $xmlPath = Join-Path $OutputDirectory "${baseName}_${timestamp}.xml"
            $xmlData | Export-Clixml -Path $xmlPath -Depth 10
            Write-Host "Data exported to XML: $xmlPath" -ForegroundColor Green
        }
    } catch {
        Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Failed to export to Excel: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Falling back to CSV export..." -ForegroundColor Yellow
        
        # Fallback to CSV
        $csvPath = if ($ExcelPath) { $ExcelPath -replace '\.xlsx$', '.csv' } else { Join-Path $OutputDirectory "Users_Export.csv" }
        $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Data exported to CSV: $csvPath" -ForegroundColor Green
    }
}

# Display security summary if we have user data
if ($allLoginHistory -and $allLoginHistory.Count -gt 0) {
    Show-SecuritySummary -UserData $allLoginHistory -LoginData $allLoginHistory
}

Write-Host ""
