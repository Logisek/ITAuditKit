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
    
    [Parameter(Mandatory=$false, HelpMessage="Show minimal information when listing users (User, User Rights, MFA Enforcement, Roles, Last Login)")]
    [switch]$Minimal,
    
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
    Write-Host "  -Minimal                : Show minimal info when listing users (User, Rights, MFA, Roles, Login)"
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
     -not $Minimal)) {
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
        [int]$Max
    )
    
    Write-Verbose "Retrieving Entra ID users..."
    
    try {
        # Check if Microsoft.Graph modules are installed
        $requiredModules = @('Microsoft.Graph.Users', 'Microsoft.Graph.Authentication')
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
                    
                    # Get PIN last set date from Windows Hello for Business method
                    if ($windowsHelloMethod) {
                        try {
                            # Check if the method has creation date or last modified date
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
            
            $userList += [PSCustomObject]@{
                TimeStamp = if ($lastSignIn) { [DateTime]$lastSignIn } else { [DateTime]::MinValue }
                UserName = $mgUser.UserPrincipalName
                DisplayName = $mgUser.DisplayName
                Mail = $mgUser.Mail
                Roles = $rolesString
                UserRights = $userRights
                MFAStatus = $mfaStatus
                MFAEnforcement = $mfaEnforcement
                PINLastSet = $pinLastSet
                AppDisplayName = $signInType
                Status = if ($mgUser.AccountEnabled) { "Enabled" } else { "Disabled" }
                Enabled = $mgUser.AccountEnabled
                PasswordLastSet = $mgUser.LastPasswordChangeDateTime
                CreatedDate = $mgUser.CreatedDateTime
                Source = "Entra ID"
            }
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
        $entraIDHistory = Get-EntraIDUsersList -User $UserName -Max $MaxRecords
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
        if ($Minimal) {
            # Minimal view - show only essential information
            $allLoginHistory | Format-Table -AutoSize -Property `
                @{Label='User'; Expression={$_.UserName}},
                @{Label='User Rights'; Expression={if ($_.UserRights) { $_.UserRights } else { "-" }}},
                @{Label='MFA Enforcement'; Expression={if ($_.MFAEnforcement) { $_.MFAEnforcement } else { "-" }}},
                @{Label='Roles'; Expression={if ($_.Roles) { $_.Roles } else { "-" }}},
                @{Label='Last Login'; Expression={
                    if ($_.TimeStamp -eq [DateTime]::MinValue) { 
                        "Never" 
                    } else { 
                        $_.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss') 
                    }
                }}
        } else {
            # Extended view - show all information
            $allLoginHistory | Format-Table -AutoSize -Property `
                @{Label='User'; Expression={$_.UserName}},
                @{Label='Display Name'; Expression={$_.DisplayName}},
                @{Label='Email'; Expression={if ($_.Mail) { $_.Mail } else { "-" }}},
                @{Label='User Rights'; Expression={if ($_.UserRights) { $_.UserRights } else { "-" }}},
                @{Label='MFA Status'; Expression={if ($_.MFAStatus) { $_.MFAStatus } else { "-" }}},
                @{Label='MFA Enforcement'; Expression={if ($_.MFAEnforcement) { $_.MFAEnforcement } else { "-" }}},
                @{Label='PIN Last Set'; Expression={
                    if ($_.PINLastSet) { 
                        if ($_.PINLastSet -is [DateTime]) {
                            $_.PINLastSet.ToString('yyyy-MM-dd HH:mm:ss')
                        } else {
                            ([DateTime]$_.PINLastSet).ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    } else { 
                        "-" 
                    }
                }},
                @{Label='Roles'; Expression={if ($_.Roles) { $_.Roles } else { "-" }}},
                @{Label='Last Login'; Expression={
                    if ($_.TimeStamp -eq [DateTime]::MinValue) { 
                        "Never" 
                    } else { 
                        $_.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss') 
                    }
                }},
                @{Label='Password Last Set'; Expression={
                    if ($_.PasswordLastSet) { 
                        if ($_.PasswordLastSet -is [DateTime]) {
                            $_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss')
                        } else {
                            ([DateTime]$_.PasswordLastSet).ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    } else { 
                        "-" 
                    }
                }},
                @{Label='Login Type'; Expression={
                    if ($_.AppDisplayName -and $_.AppDisplayName -ne '-') { $_.AppDisplayName }
                    elseif ($_.LogonType) { $_.LogonType }
                    else { "-" }
                }},
                @{Label='Status'; Expression={$_.Status}},
                @{Label='Source'; Expression={$_.Source}},
                @{Label='Computer/DC'; Expression={
                    if ($_.Computer) { $_.Computer }
                    elseif ($_.DomainController) { $_.DomainController }
                    else { "-" }
                }},
                @{Label='Domain'; Expression={if ($_.Domain) { $_.Domain } else { "-" }}},
                @{Label='Enabled'; Expression={
                    if ($null -ne $_.Enabled) { $_.Enabled } else { "-" }
                }}
        }
        
        Write-Host ""
        return
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
                @{Label='PIN Last Set'; Expression={
                    if ($_.PINLastSet) { 
                        if ($_.PINLastSet -is [DateTime]) {
                            $_.PINLastSet.ToString('yyyy-MM-dd HH:mm:ss')
                        } else {
                            ([DateTime]$_.PINLastSet).ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    } else { 
                        "-" 
                    }
                }},
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
                @{Label='PIN Last Set'; Expression={
                    if ($_.PINLastSet) { 
                        if ($_.PINLastSet -is [DateTime]) {
                            $_.PINLastSet.ToString('yyyy-MM-dd HH:mm:ss')
                        } else {
                            ([DateTime]$_.PINLastSet).ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    } else { 
                        "-" 
                    }
                }},
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
                @{Label='PIN Last Set'; Expression={
                    if ($_.PINLastSet) { 
                        if ($_.PINLastSet -is [DateTime]) {
                            $_.PINLastSet.ToString('yyyy-MM-dd HH:mm:ss')
                        } else {
                            ([DateTime]$_.PINLastSet).ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    } else { 
                        "-" 
                    }
                }},
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
            @{Label='PIN Last Set'; Expression={
                if ($_.PINLastSet) { 
                    if ($_.PINLastSet -is [DateTime]) {
                        $_.PINLastSet.ToString('yyyy-MM-dd HH:mm:ss')
                    } else {
                        ([DateTime]$_.PINLastSet).ToString('yyyy-MM-dd HH:mm:ss')
                    }
                } else { 
                    "-" 
                }
            }},
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

Write-Host ""
