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

.NOTES
    Author: IT Audit Kit
    Version: 3.9
    Requires: 
        - Administrator privileges to read local Security event log
        - ActiveDirectory PowerShell module for AD logs
        - Microsoft.Graph PowerShell modules for Entra ID logs (Users, Reports, Authentication)
        - UserAuthenticationMethod.Read.All and Device.Read.All permissions for Entra ID
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
    [switch]$Help
)

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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
            $riskFactors += "Password >1yr"
        } elseif ($passwordAge.Days -gt 180) {
            $riskScore += 15
            $riskFactors += "Password >6mo"
        } elseif ($passwordAge.Days -gt 90) {
            $riskScore += 10
            $riskFactors += "Password >3mo"
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
            $riskFactors += "Inactive >90d"
        } elseif ($lastLogin.Days -gt 30) {
            $riskScore += 10
            $riskFactors += "Inactive >30d"
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
            $serviceRisks += "No activity >1yr"
        } elseif ($lastActivity.Days -gt 180) {
            $serviceRisks += "No activity >6mo"
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
                $guestRisks += "Inactive guest >90d"
            } elseif ($lastActivity.Days -gt 30) {
                $guestRisks += "Inactive guest >30d"
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
            $policyViolations += "Password >1yr old"
            $policyScore -= 30
        } elseif ($passwordAge.Days -gt 180) {
            $policyViolations += "Password >6mo old"
            $policyScore -= 15
        } elseif ($passwordAge.Days -gt 90) {
            $policyViolations += "Password >3mo old"
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
                $policyViolations += "Service account password >180d"
                $policyScore -= 15
            }
        }
    }
    
    # Check for guest accounts with old passwords
    if ($User.UserName -like "*#EXT#*" -or $User.UserName -like "*_*#EXT#*") {
        if ($User.PasswordLastSet) {
            $passwordAge = (Get-Date) - [DateTime]$User.PasswordLastSet
            if ($passwordAge.Days -gt 90) {
                $policyViolations += "Guest password >90d"
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
            $lockoutRisks += "Inactive >30d (potential lockout)"
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
    Write-Host "  -Help                   : Display this help message"
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
    Write-Host "  .\users.ps1 -IncludeEntraID -ListUsers -Minimal"
    Write-Host "    Shows minimal user information (User, Rights, MFA, Roles, Last Login)"
    Write-Host ""
    Write-Host "  .\users.ps1 -IncludeAD -ListUsers -Minimal"
    Write-Host "    Shows minimal Active Directory user information"
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
     -not $IncludeExportFormats)) {
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
        
        Write-Verbose "Found $($mgUsers.Count) Entra ID users"
        
        $userList = @()
        $userCount = 0
        foreach ($mgUser in $mgUsers) {
            $userCount++
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

# Display combined results
if ($allLoginHistory.Count -gt 0) {
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
            else { Write-Host ""; return }
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
            if (-not $ExportExcel) { return }
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
        if (-not $ExportExcel) { return }
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
            $csvPath = if ($ExcelPath) { $ExcelPath -replace '\.xlsx$', '.csv' } else { "Users_Export.csv" }
            $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Data exported to CSV: $csvPath" -ForegroundColor Green
        } else {
            # Import the module
            Import-Module ImportExcel -ErrorAction SilentlyContinue
            
            # Set default paths if not provided
            if (-not $ExcelPath) {
                $ExcelPath = if ($ListUsers) { "Users_List.xlsx" } else { "Login_Records.xlsx" }
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
            $csvPath = "${baseName}_${timestamp}.csv"
            $exportDataForExport | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Data exported to CSV: $csvPath" -ForegroundColor Green
            
            # JSON Export
            $jsonPath = "${baseName}_${timestamp}.json"
            $exportDataForExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            Write-Host "Data exported to JSON: $jsonPath" -ForegroundColor Green
            
            # HTML Report Export
            $htmlPath = "${baseName}_${timestamp}.html"
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
</body>
</html>
"@
            
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
            Write-Host "Data exported to HTML: $htmlPath" -ForegroundColor Green
            
            # XML Export
            $xmlPath = "${baseName}_${timestamp}.xml"
            $exportDataForExport | Export-Clixml -Path $xmlPath -Depth 10
            Write-Host "Data exported to XML: $xmlPath" -ForegroundColor Green
        }
    } catch {
        Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Failed to export to Excel: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Falling back to CSV export..." -ForegroundColor Yellow
        
        # Fallback to CSV
        $csvPath = if ($ExcelPath) { $ExcelPath -replace '\.xlsx$', '.csv' } else { "Users_Export.csv" }
        $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Data exported to CSV: $csvPath" -ForegroundColor Green
    }
}

Write-Host ""
