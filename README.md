# ITAuditKit - IT Security Audit Toolkit

> **Comprehensive PowerShell toolkit for IT security auditing, user account analysis, and compliance reporting**

[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Features](#features)
6. [Step-by-Step Usage Guide](#step-by-step-usage-guide)
7. [Command Reference](#command-reference)
8. [Export Formats](#export-formats)
9. [Compliance Frameworks](#compliance-frameworks)
10. [Real-World Examples](#real-world-examples)
11. [Troubleshooting](#troubleshooting)
12. [Advanced Topics](#advanced-topics)

---

## 🎯 Overview

**ITAuditKit** is a professional-grade PowerShell toolkit designed for IT administrators, security auditors, and compliance officers. It provides comprehensive user account auditing, security risk assessment, and compliance reporting across multiple platforms.

### What Can It Do?

✅ **Multi-Source Data Collection**
- Microsoft Entra ID (Azure AD) - Cloud identities
- Active Directory - On-premises identities  
- Local Windows accounts - Workstation/server accounts

✅ **Security Analysis**
- MFA status and enforcement
- Privileged account identification
- Password policy compliance
- Account lockout risks
- Security risk scoring (color-coded)
- Windows Hello for Business (WHfB) status

✅ **Compliance Reporting**
- 7 major frameworks supported: SOX, HIPAA, GDPR, PCI-DSS, ISO27001, NIST, CIS
- Pass/Fail status with detailed metrics
- Automated compliance assessment

✅ **Advanced Filtering**
- Filter by department, location, job title
- Filter by MFA status, risk level, account status
- Filter by login activity and date ranges
- Target specific user populations

✅ **Multiple Export Formats**
- Excel (recommended) - Multiple worksheets with formatting
- CSV - Data analysis friendly
- JSON - Automation and API integration
- HTML - Professional reports for stakeholders
- XML - PowerShell native format

✅ **Performance Features**
- Caching system for faster repeated queries
- Configurable cache expiry
- Progress indicators
- Summary statistics

---

## 💻 System Requirements

### Required
- **PowerShell 7.0 or higher** ⚠️ **IMPORTANT**
  - PowerShell 5.1 is NOT supported
  - The script will automatically check and prompt if needed
  - Download: [PowerShell 7+](https://github.com/PowerShell/PowerShell/releases)

### Permissions Required

| Data Source | Required Permissions |
|------------|---------------------|
| **Entra ID** | Global Reader, User Administrator, or similar role with user read permissions |
| **Active Directory** | Domain user with read access to AD |
| **Local Accounts** | Local Administrator rights on the target machine |

### Optional PowerShell Modules

```powershell
# For Excel export functionality (highly recommended)
Install-Module ImportExcel -Scope CurrentUser

# For Entra ID (Azure AD) access
Install-Module Microsoft.Graph -Scope CurrentUser
```

---

## 📦 Installation

### Step 1: Download the Toolkit
```powershell
# Clone the repository
git clone https://github.com/yourusername/ITAuditKit.git
cd ITAuditKit

# Or download and extract the ZIP file
```

### Step 2: Verify PowerShell Version
```powershell
# Check your PowerShell version
$PSVersionTable.PSVersion

# Should show: Major 7 or higher
# If not, download PowerShell 7+ from:
# https://github.com/PowerShell/PowerShell/releases
```

### Step 3: Install Optional Modules
```powershell
# For Excel export (recommended)
Install-Module ImportExcel -Scope CurrentUser -Force

# For Microsoft Entra ID access
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### Step 4: Set Execution Policy (if needed)
```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 5: Test Installation
```powershell
# Navigate to the toolkit directory
cd C:\Path\To\ITAuditKit

# Run a basic test
.\users\users.ps1 -IncludeLocal -ListUsers -MaxRecords 5
```

---

## 🚀 Quick Start

### Absolute Basics - Your First Commands

#### 1. List All Entra ID Users (Cloud)
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers
```
**What it does:** Connects to Microsoft Graph, retrieves all cloud users, displays in console

#### 2. List Local Users
```powershell
.\users\users.ps1 -IncludeLocal -ListUsers
```
**What it does:** Lists all local accounts on the current machine

#### 3. List Active Directory Users
```powershell
.\users\users.ps1 -IncludeAD -ListUsers
```
**What it does:** Queries your on-premises Active Directory for user accounts

#### 4. Export to Excel
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath ".\MyReport.xlsx"
```
**What it does:** Creates an Excel file with all user data

#### 5. Generate Compliance Report
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "SOX" -ExportExcel -ExcelPath ".\SOX_Audit.xlsx"
```
**What it does:** Creates compliance report with Excel export

#### 6. Organize Exports in Custom Directory
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -OutputDirectory "C:\Reports\SecurityAudits" -ExportExcel -ExcelPath "Audit.xlsx" -IncludeExportFormats
```
**What it does:** Creates all export files in the specified directory (creates folder if it doesn't exist)

---

### 💡 Pro Tip: Organizing Your Exports

The `-OutputDirectory` parameter helps you keep reports organized:

```powershell
# Organize by date
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -OutputDirectory "C:\Reports\$(Get-Date -Format 'yyyy-MM')" `
    -ExportExcel -ExcelPath "SecurityAudit.xlsx"

# Organize by department
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -FilterByDepartment "IT" `
    -OutputDirectory "C:\Reports\Departments\IT" `
    -ExportExcel -ExcelPath "IT_Audit.xlsx"

# Organize by compliance framework
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -ComplianceFramework "SOX" `
    -OutputDirectory "C:\ComplianceReports\SOX\2025" `
    -ExportExcel -ExcelPath "SOX_Q1_2025.xlsx" `
    -IncludeExportFormats
```

**Benefits:**
- ✅ Automatic folder creation if it doesn't exist
- ✅ All exports (Excel, CSV, JSON, HTML, XML) go to the same directory
- ✅ Easy to organize by date, department, or compliance framework
- ✅ Simplifies report archival and sharing
- ✅ Works with relative and absolute paths

---

## ✨ Features

### 1. Multi-Source Data Collection

#### Entra ID (Azure AD / Microsoft 365)
Retrieves cloud identity information including:
- User principal name, display name, email
- MFA status and authentication methods
- Sign-in activity and last login
- Account enabled/disabled status
- Assigned roles and group memberships
- Department, job title, office location
- Guest user identification

#### Active Directory (On-Premises)
Retrieves on-premises directory information including:
- SAM account name, user principal name
- Account status (enabled/disabled/locked)
- Password last set, password expiry
- Last logon timestamp
- Group memberships
- Organizational unit (OU)
- Account creation date

#### Local Accounts
Retrieves local machine account information including:
- Local usernames
- Account status
- Login history from event logs
- Last interactive logon
- Account creation date
- Administrative rights

### 2. Security Risk Scoring

The script automatically calculates security risk scores based on:

- **MFA Status** (30% weight)
  - No MFA = High risk
  - Partial MFA = Medium risk
  - Full MFA = Low risk

- **Password Policy** (25% weight)
  - Never expires = High risk
  - Old passwords = Medium risk
  - Strong policies = Low risk

- **Account Activity** (20% weight)
  - Inactive accounts = High risk
  - Stale accounts = Medium risk
  - Active accounts = Low risk

- **Privileged Access** (25% weight)
  - Privileged without MFA = Critical risk
  - Privileged with MFA = Monitored

**Risk Levels:**
- 🔴 **Critical** (90-100) - Immediate action required
- 🟠 **High** (70-89) - Urgent attention needed
- 🟡 **Medium** (40-69) - Should be addressed
- 🟢 **Low** (20-39) - Minor concerns
- ⚪ **Minimal** (0-19) - Good security posture

### 3. Advanced Filtering

#### Demographic Filters
```powershell
-FilterByDepartment "IT"         # Filter by department
-FilterByLocation "New York"      # Filter by office location
-FilterByJobTitle "Manager"       # Filter by job title
```

#### Security Filters
```powershell
-ShowOnlyNoMFA                    # Only users without MFA
-ShowOnlyPrivileged              # Only admin/privileged accounts
-ShowOnlyDisabled                # Only disabled accounts
-ShowOnlyGuests                  # Only guest/external users
-FilterByRiskLevel "Critical"    # By risk level
```

#### Activity Filters
```powershell
-InactiveDays 90                 # Inactive for 90+ days
-LastLoginAfter "2024-01-01"     # Logged in after date
-LastLoginBefore "2024-12-31"    # Logged in before date
```

### 4. Caching System

Speed up repeated queries with intelligent caching:

```powershell
# First run: fetches fresh data (takes ~10 seconds)
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache

# Second run: uses cached data (takes ~2 seconds)
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -FilterByDepartment "IT"

# Control cache expiry
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -CacheExpiryMinutes 30

# Clear cache when you need fresh data
.\users\users.ps1 -ClearCache
```

**Cache Benefits:**
- 70% faster on repeated queries
- Reduces API calls to Microsoft Graph
- Ideal for running multiple filtered reports
- Automatic expiry ensures data freshness

### 5. Compliance Reporting

Generate automated compliance reports for major frameworks:

| Framework | Full Name | Focus Areas |
|-----------|-----------|-------------|
| **SOX** | Sarbanes-Oxley Act | Financial data integrity, access controls, segregation of duties |
| **HIPAA** | Health Insurance Portability and Accountability Act | Protected Health Information (PHI) access controls |
| **GDPR** | General Data Protection Regulation | Data subject rights, access control, data minimization |
| **PCI-DSS** | Payment Card Industry Data Security Standard | Cardholder data protection, strong access control |
| **ISO27001** | Information Security Management | Access control, user management, authentication |
| **NIST** | NIST Cybersecurity Framework | Identify, Protect, Detect, Respond, Recover |
| **CIS** | CIS Controls v8 | Critical security controls, account management |

**Each report includes:**
- ✅/❌ Pass/Fail status
- Detailed metrics and counts
- Control point mapping
- Specific findings
- Risk indicators
- Actionable recommendations

---

## 📖 Step-by-Step Usage Guide

### Scenario 1: Basic User Audit

**Goal:** Get a list of all users in your organization

**Steps:**
1. Open PowerShell 7
2. Navigate to ITAuditKit folder
3. Run the appropriate command for your environment:

```powershell
# For Microsoft 365 / Entra ID
.\users\users.ps1 -IncludeEntraID -ListUsers

# For Active Directory
.\users\users.ps1 -IncludeAD -ListUsers

# For both cloud and on-premises
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers
```

4. Review the console output
5. Look for the summary statistics at the bottom

---

### Scenario 2: Security Risk Assessment

**Goal:** Identify high-risk accounts that need immediate attention

**Steps:**
1. Run with risk scoring enabled:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore
```

2. Filter for critical/high risk only:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore -FilterByRiskLevel "Critical"
```

3. Export findings to Excel:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore -FilterByRiskLevel "Critical" -ExportExcel -ExcelPath ".\HighRisk_Users.xlsx"
```

4. Open the Excel file and review the "Risk Score" column
5. Color coding helps identify critical issues quickly

---

### Scenario 3: MFA Compliance Check

**Goal:** Find all users without MFA enabled

**Steps:**
1. Identify users without MFA:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ShowOnlyNoMFA
```

2. Export for remediation:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ShowOnlyNoMFA -ExportExcel -ExcelPath ".\Users_NoMFA.xlsx"
```

3. Focus on privileged accounts first:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ShowOnlyNoMFA -ShowOnlyPrivileged -ExportExcel -ExcelPath ".\Privileged_NoMFA_URGENT.xlsx"
```

4. Share the Excel file with your security team
5. Track remediation progress

---

### Scenario 4: Inactive Account Cleanup

**Goal:** Find and disable accounts that haven't been used in 90 days

**Steps:**
1. Find inactive accounts:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -InactiveDays 90
```

2. Export the list:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -InactiveDays 90 -ExportExcel -ExcelPath ".\Inactive_90days.xlsx"
```

3. Review the Excel file with management
4. Get approval for account disabling
5. Use the list to disable/delete accounts in your directory

---

### Scenario 5: Department-Specific Audit

**Goal:** Audit all IT department users

**Steps:**
1. List IT department users:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByDepartment "IT"
```

2. Check for security issues:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByDepartment "IT" -ShowOnlyNoMFA
```

3. Generate comprehensive report:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByDepartment "IT" -IncludeRiskScore -IncludeMFADetails -IncludeGroups -ExportExcel -ExcelPath ".\IT_Department_Audit.xlsx"
```

4. Review with IT management
5. Track any required changes

---

### Scenario 6: Compliance Report for Auditors

**Goal:** Generate SOX compliance report for annual audit

**Steps:**
1. Generate SOX report with all data:
```powershell
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers -ComplianceFramework "SOX" -ExportExcel -ExcelPath ".\SOX_Audit_2025.xlsx" -IncludeExportFormats
```

2. This creates:
   - Excel file with user data + compliance worksheet
   - CSV files for data analysis
   - JSON file for automation
   - HTML report for presentation
   - XML for archival

3. Review the compliance worksheet in Excel
4. Address any "NON-COMPLIANT" or "FAIL" items
5. Re-run after remediation to verify compliance

---

### Scenario 7: Fast Repeated Queries with Caching

**Goal:** Run multiple filtered reports quickly

**Steps:**
1. First query with cache enabled:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache
```

2. Now run multiple filters (all use cached data):
```powershell
# IT department
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -FilterByDepartment "IT"

# Finance department
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -FilterByDepartment "Finance"

# Privileged accounts
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -ShowOnlyPrivileged

# No MFA
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -ShowOnlyNoMFA
```

3. All queries run 70% faster using cached data
4. Cache expires after 60 minutes (default)
5. Use `-ClearCache` when you need fresh data

---

### Scenario 8: Complete Compliance Assessment

**Goal:** Generate compliance reports for all frameworks

**Steps:**
1. Run comprehensive compliance check:
```powershell
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers -ComplianceFramework "All" -ExportExcel -ExcelPath ".\Full_Compliance_2025.xlsx" -IncludeExportFormats
```

2. This generates reports for all 7 frameworks:
   - SOX (Financial)
   - HIPAA (Healthcare)
   - GDPR (Privacy)
   - PCI-DSS (Payment cards)
   - ISO27001 (Information security)
   - NIST (Cybersecurity)
   - CIS (Critical controls)

3. Review each framework's status
4. Create remediation plan for any failures
5. Track progress over time

---

## 📚 Command Reference

### Basic Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-IncludeEntraID` | Include Entra ID (Azure AD) users | `-IncludeEntraID` |
| `-IncludeAD` | Include Active Directory users | `-IncludeAD` |
| `-IncludeLocal` | Include local machine users | `-IncludeLocal` |
| `-ListUsers` | Display user list format | `-ListUsers` |
| `-MaxRecords <int>` | Limit number of records per source | `-MaxRecords 100` |
| `-Minimal` | Show minimal output (fewer columns) | `-Minimal` |
| `-OutGridView` | Display in interactive grid | `-OutGridView` |

### Filtering Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-FilterByDepartment <string>` | Filter by department | `-FilterByDepartment "IT"` |
| `-FilterByLocation <string>` | Filter by location | `-FilterByLocation "London"` |
| `-FilterByJobTitle <string>` | Filter by job title | `-FilterByJobTitle "Manager"` |
| `-FilterByRiskLevel <string>` | Filter by risk level | `-FilterByRiskLevel "Critical"` |
| `-ShowOnlyNoMFA` | Show only users without MFA | `-ShowOnlyNoMFA` |
| `-ShowOnlyPrivileged` | Show only privileged accounts | `-ShowOnlyPrivileged` |
| `-ShowOnlyDisabled` | Show only disabled accounts | `-ShowOnlyDisabled` |
| `-ShowOnlyGuests` | Show only guest users | `-ShowOnlyGuests` |
| `-InactiveDays <int>` | Show inactive users (X days) | `-InactiveDays 90` |
| `-LastLoginAfter <datetime>` | Logins after date | `-LastLoginAfter "2024-01-01"` |
| `-LastLoginBefore <datetime>` | Logins before date | `-LastLoginBefore "2024-12-31"` |

### Analysis Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-IncludeRiskScore` | Calculate security risk scores | `-IncludeRiskScore` |
| `-IncludeMFADetails` | Include MFA method details | `-IncludeMFADetails` |
| `-IncludeGroups` | Include group memberships | `-IncludeGroups` |
| `-IncludePIN` | Include WHfB PIN status | `-IncludePIN` |
| `-IncludePasswordPolicy` | Include password policy analysis | `-IncludePasswordPolicy` |
| `-IncludeLockoutStatus` | Include account lockout info | `-IncludeLockoutStatus` |
| `-IncludeAppPermissions` | Include app permissions | `-IncludeAppPermissions` |

### Export Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-ExportExcel` | Enable Excel export | `-ExportExcel` |
| `-ExcelPath <string>` | Excel file path (default: Users_List.xlsx) | `-ExcelPath ".\Report.xlsx"` |
| `-ExcelWorksheet <string>` | Worksheet name (default: Users) | `-ExcelWorksheet "Users"` |
| `-OutputDirectory <string>` | Output directory for all exported files (default: current directory) | `-OutputDirectory "C:\Reports"` |
| `-IncludeExportFormats` | Export to all formats (CSV, JSON, HTML, XML) | `-IncludeExportFormats` |

### Compliance Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-ComplianceFramework <string[]>` | Generate compliance report | `-ComplianceFramework "SOX"` |
| | Available: SOX, HIPAA, GDPR, PCI-DSS, ISO27001, NIST, CIS, All | `-ComplianceFramework "All"` |

### Performance Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-UseCache` | Use cached data if available | `-UseCache` |
| `-CacheExpiryMinutes <int>` | Cache expiry (default: 60) | `-CacheExpiryMinutes 30` |
| `-ClearCache` | Clear cache before running | `-ClearCache` |

---

## 📊 Export Formats

### 1. Excel Export (Recommended)

**Best for:** Comprehensive reports, sharing with stakeholders, data analysis

```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath ".\Report.xlsx"
```

**Features:**
- Multiple worksheets (Users + Compliance)
- Professional table formatting
- Auto-sized columns
- Frozen headers
- Color-coded risk levels
- Easy to filter and sort

**Compliance Integration:**
- Separate "Compliance" worksheet
- All frameworks in one workbook
- Clear PASS/FAIL indicators

---

### 2. CSV Export

**Best for:** Data analysis in Excel/Python/R, importing to other systems

```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath ".\Report.xlsx" -IncludeExportFormats
```

**Creates:**
- `Users_List_YYYYMMDD_HHMMSS.csv` - User data
- `Users_List_Compliance_YYYYMMDD_HHMMSS.csv` - Compliance data (separate file)

**Features:**
- Universal compatibility
- Easy to import/parse
- Works with any data analysis tool
- UTF-8 encoding

---

### 3. JSON Export

**Best for:** Automation, API integration, custom dashboards

```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath ".\Report.xlsx" -IncludeExportFormats
```

**Structure:**
```json
{
  "UserData": [...],
  "ComplianceReports": [...],
  "GeneratedAt": "2025-10-16T00:00:00",
  "TotalUsers": 150
}
```

**Use Cases:**
- Feed data to monitoring tools
- Custom PowerBI dashboards
- Automated workflows
- Integration with SIEM systems

---

### 4. HTML Export

**Best for:** Presentations, executive reports, sharing via email/web

```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath ".\Report.xlsx" -IncludeExportFormats
```

**Features:**
- Professional styling
- Color-coded risk levels
- Compliance section with PASS/FAIL colors
- Printable format
- No software required to view

**Perfect for:**
- Board presentations
- Non-technical stakeholders
- Quick email reports
- Publishing to intranet

---

### 5. XML Export

**Best for:** PowerShell workflows, archival, regulatory compliance

```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath ".\Report.xlsx" -IncludeExportFormats
```

**Features:**
- PowerShell native format
- Can be re-imported with `Import-Clixml`
- Preserves object types
- Deep serialization
- Audit trail friendly

---

## 🎓 Real-World Examples

### Example 1: Weekly Security Review

```powershell
# Monday morning security check - saves to dedicated reports folder
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -IncludeRiskScore `
    -FilterByRiskLevel "Critical" `
    -OutputDirectory "C:\SecurityReports" `
    -ExportExcel -ExcelPath "Weekly_Security_$(Get-Date -Format 'yyyy-MM-dd').xlsx"
```

**Use Case:** Weekly review of critical security issues  
**Time:** ~15 seconds  
**Output:** Excel file with high-risk accounts in C:\SecurityReports folder

---

### Example 2: Pre-Audit Compliance Check

```powershell
# Comprehensive pre-audit assessment - organized in audit folder
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers `
    -ComplianceFramework "All" `
    -IncludeRiskScore `
    -IncludeMFADetails `
    -IncludeGroups `
    -OutputDirectory "C:\AuditReports\2025" `
    -ExportExcel -ExcelPath "Pre-Audit_Assessment_$(Get-Date -Format 'yyyy-MM-dd').xlsx" `
    -IncludeExportFormats
```

**Use Case:** Annual audit preparation  
**Time:** ~45 seconds  
**Output:** Complete audit package (Excel, CSV, JSON, HTML, XML) in C:\AuditReports\2025

---

### Example 3: Departmental Security Report

```powershell
# Finance department monthly review
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -FilterByDepartment "Finance" `
    -IncludeRiskScore `
    -IncludeMFADetails `
    -ComplianceFramework "SOX","PCI-DSS" `
    -ExportExcel -ExcelPath ".\Finance_Security_Report_$(Get-Date -Format 'yyyy-MM').xlsx"
```

**Use Case:** Monthly departmental security review  
**Time:** ~10 seconds  
**Output:** Excel with Finance users + SOX/PCI-DSS compliance

---

### Example 4: Privileged Account Audit

```powershell
# Quarterly privileged account review
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers `
    -ShowOnlyPrivileged `
    -IncludeRiskScore `
    -IncludeMFADetails `
    -IncludeGroups `
    -IncludePasswordPolicy `
    -ComplianceFramework "SOX","ISO27001","CIS" `
    -ExportExcel -ExcelPath ".\Privileged_Accounts_Q$(Get-Date -Format 'MM')_2025.xlsx" `
    -IncludeExportFormats
```

**Use Case:** Quarterly privileged access review  
**Time:** ~20 seconds  
**Output:** Complete privileged account assessment

---

### Example 5: Inactive Account Cleanup

```powershell
# Find accounts inactive for 90+ days
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -InactiveDays 90 `
    -ExportExcel -ExcelPath ".\Inactive_Accounts_Cleanup_$(Get-Date -Format 'yyyy-MM-dd').xlsx"

# Focus on non-privileged accounts first
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -InactiveDays 90 `
    -ShowOnlyDisabled:$false `
    -ExportExcel -ExcelPath ".\Inactive_Enabled_Accounts.xlsx"
```

**Use Case:** Account hygiene and cleanup  
**Time:** ~10 seconds  
**Output:** List of accounts to review for disabling

---

### Example 6: Guest User Review

```powershell
# Quarterly external user access review
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -ShowOnlyGuests `
    -IncludeRiskScore `
    -IncludeMFADetails `
    -ComplianceFramework "GDPR","ISO27001" `
    -ExportExcel -ExcelPath ".\Guest_User_Review_Q$(Get-Date -Format 'MM')_2025.xlsx"
```

**Use Case:** External access governance  
**Time:** ~15 seconds  
**Output:** All guest users with compliance check

---

### Example 7: New Hire Onboarding Verification

```powershell
# Check accounts created in last 30 days
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -LastLoginAfter (Get-Date).AddDays(-30) `
    -IncludeMFADetails `
    -ExportExcel -ExcelPath ".\New_Hires_$(Get-Date -Format 'yyyy-MM').xlsx"
```

**Use Case:** Verify new employee account setup  
**Time:** ~10 seconds  
**Output:** Recent accounts and their security posture

---

### Example 8: Password Policy Compliance

```powershell
# Find users with password policy violations
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers `
    -IncludePasswordPolicy `
    -IncludeRiskScore `
    -ComplianceFramework "PCI-DSS","ISO27001" `
    -ExportExcel -ExcelPath ".\Password_Policy_Review_$(Get-Date -Format 'yyyy-MM-dd').xlsx"
```

**Use Case:** Password policy enforcement  
**Time:** ~20 seconds  
**Output:** Users with weak/old passwords

---

### Example 9: Automated Daily Report

```powershell
# Create scheduled task for daily monitoring
$Script = @"
.\users\users.ps1 -IncludeEntraID -ListUsers ``
    -UseCache ``
    -FilterByRiskLevel "Critical" ``
    -ShowOnlyNoMFA ``
    -OutputDirectory "C:\Reports\Daily" ``
    -ExportExcel -ExcelPath "Security_`$(Get-Date -Format 'yyyy-MM-dd').xlsx"

# Email if critical issues found
`$reportPath = "C:\Reports\Daily\Security_`$(Get-Date -Format 'yyyy-MM-dd').xlsx"
`$report = Import-Excel `$reportPath
if (`$report.Count -gt 0) {
    Send-MailMessage -To "security@company.com" ``
        -Subject "ALERT: Critical Security Issues Detected" ``
        -Body "`$(`$report.Count) critical issues found. See attached report." ``
        -Attachments `$reportPath
}
"@

# Save and schedule
$Script | Out-File "C:\Scripts\DailySecurityCheck.ps1"
```

**Use Case:** Automated daily security monitoring  
**Time:** Runs automatically  
**Output:** Daily Excel reports + email alerts

---

### Example 10: Multi-Source Comprehensive Audit

```powershell
# Complete environment audit (cloud + on-prem + local)
.\users\users.ps1 -IncludeEntraID -IncludeAD -IncludeLocal -ListUsers `
    -IncludeRiskScore `
    -IncludeMFADetails `
    -IncludeGroups `
    -IncludePasswordPolicy `
    -IncludeLockoutStatus `
    -ComplianceFramework "All" `
    -ExportExcel -ExcelPath ".\Complete_Environment_Audit_$(Get-Date -Format 'yyyy-MM-dd').xlsx" `
    -IncludeExportFormats `
    -UseCache
```

**Use Case:** Comprehensive security audit  
**Time:** ~60 seconds (first run), ~20 seconds (cached)  
**Output:** Complete audit package with all data sources and compliance

---

## 📘 Complete Feature Examples

This section provides examples for **EVERY available feature**, not just the major ones.

### Basic Parameters

#### `-UserName` - Query Specific User
```powershell
# Find specific user across all sources
.\users\users.ps1 -IncludeEntraID -IncludeAD -IncludeLocal -UserName "john.doe"
```

#### `-MaxRecords` - Limit Results
```powershell
# Get only first 50 users (faster for testing)
.\users\users.ps1 -IncludeEntraID -ListUsers -MaxRecords 50
```

#### `-ComputerName` - Target Specific Computer
```powershell
# Query remote computer
.\users\users.ps1 -IncludeLocal -ListUsers -ComputerName "SERVER01"
```

---

### Data Source Parameters

#### `-IncludeLocal` - Local Accounts
```powershell
# Audit local accounts on this machine
.\users\users.ps1 -IncludeLocal -ListUsers
```

#### `-IncludeAD` - Active Directory
```powershell
# Audit on-premises AD users
.\users\users.ps1 -IncludeAD -ListUsers
```

#### `-IncludeEntraID` - Cloud Identities
```powershell
# Audit Microsoft 365 / Azure AD users
.\users\users.ps1 -IncludeEntraID -ListUsers
```

#### Combined Sources
```powershell
# Comprehensive audit across all identity systems
.\users\users.ps1 -IncludeEntraID -IncludeAD -IncludeLocal -ListUsers
```

---

### Display and Output Parameters

#### `-ListUsers` - User List Format
```powershell
# Show users instead of login events
.\users\users.ps1 -IncludeEntraID -ListUsers
```

#### `-IncludePIN` - Windows Hello for Business Status
```powershell
# Check WHfB PIN registration and last WHfB sign-in
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludePIN
```

#### `-Minimal` - Compact View
```powershell
# Show only essential columns (User, Rights, MFA, Roles, Last Login)
.\users\users.ps1 -IncludeEntraID -ListUsers -Minimal
```

#### `-OutGridView` - Interactive GUI Table
```powershell
# Display in sortable, filterable grid view
.\users\users.ps1 -IncludeEntraID -ListUsers -OutGridView
```

---

### Export Parameters

#### `-ExportExcel` - Excel Export
```powershell
# Export to Excel file
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath "Report.xlsx"
```

#### `-ExcelWorksheet` - Custom Worksheet Name
```powershell
# Specify worksheet name
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath "Report.xlsx" -ExcelWorksheet "EntraID_Users"
```

#### `-OutputDirectory` - Organize Exports
```powershell
# Save all exports to specific folder
.\users\users.ps1 -IncludeEntraID -ListUsers -OutputDirectory "C:\Reports\Monthly" -ExportExcel -ExcelPath "Users.xlsx"
```

#### `-IncludeExportFormats` - All Formats
```powershell
# Export to Excel, CSV, JSON, HTML, and XML
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath "Report.xlsx" -IncludeExportFormats
```

---

### Security Analysis Parameters

#### `-IncludeRiskScore` - Security Risk Assessment
```powershell
# Calculate security risk scores for each user
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore
```
**What it shows:** Risk level (Critical/High/Medium/Low/Minimal) with color coding

#### `-IncludePrivilegedAccounts` - Privileged Account Analysis
```powershell
# Identify and flag privileged accounts
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers -IncludePrivilegedAccounts
```
**What it shows:** Admin rights, privileged roles, elevated permissions

#### `-IncludeServiceAccounts` - Service Account Detection
```powershell
# Detect non-interactive service accounts
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers -IncludeServiceAccounts
```
**What it shows:** Service accounts, application accounts, automated accounts

#### `-IncludeGuestUsers` - Guest User Analysis
```powershell
# Analyze external/guest users
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeGuestUsers
```
**What it shows:** Guest status, access expiration, external domains

#### `-IncludePasswordPolicy` - Password Compliance
```powershell
# Check password policy compliance
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers -IncludePasswordPolicy
```
**What it shows:** Password age, complexity, expiration, policy violations

#### `-IncludeAccountLockout` - Lockout Analysis
```powershell
# Analyze lockout events and failed logins
.\users\users.ps1 -IncludeLocal -IncludeAD -ListUsers -IncludeAccountLockout
```
**What it shows:** Lockout status, failed login attempts, lockout risks

#### `-IncludeDeviceCompliance` - Device Status (Entra ID)
```powershell
# Check device compliance status
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeDeviceCompliance
```
**What it shows:** Managed devices, compliance status, device trust

#### `-IncludeConditionalAccess` - Conditional Access Policies
```powershell
# Analyze Conditional Access policy impact
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeConditionalAccess
```
**What it shows:** Applied policies, policy compliance, access restrictions

#### `-IncludeRiskySignins` - Identity Protection
```powershell
# Include risky sign-in detection
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskySignins
```
**What it shows:** Risk detections, risky sign-ins, threat indicators

#### `-IncludeGroupMembership` - Group Analysis
```powershell
# Analyze group memberships and nested groups
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers -IncludeGroupMembership
```
**What it shows:** Group memberships, nested groups, role assignments

#### `-IncludeAppPermissions` - Application Permissions
```powershell
# Audit app permissions and consent grants
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeAppPermissions
```
**What it shows:** App permissions, consent grants, OAuth apps

---

### Advanced Filtering Parameters

#### `-FilterByDepartment` - Department Filter
```powershell
# Show only IT department users
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByDepartment "IT"

# Partial match works too
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByDepartment "Information Technology"
```

#### `-FilterByLocation` - Location Filter
```powershell
# Show only users in New York office
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByLocation "New York"

# Multiple locations - run separately and combine
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByLocation "London"
```

#### `-FilterByJobTitle` - Job Title Filter
```powershell
# Show only managers
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByJobTitle "Manager"

# Show directors and above
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByJobTitle "Director"
```

#### `-LastLoginAfter` - Date Range Filter (After)
```powershell
# Users who logged in after Jan 1, 2025
.\users\users.ps1 -IncludeEntraID -ListUsers -LastLoginAfter "2025-01-01"

# Users who logged in this week
.\users\users.ps1 -IncludeEntraID -ListUsers -LastLoginAfter (Get-Date).AddDays(-7)
```

#### `-LastLoginBefore` - Date Range Filter (Before)
```powershell
# Users who logged in before Jan 1, 2025
.\users\users.ps1 -IncludeEntraID -ListUsers -LastLoginBefore "2025-01-01"

# Users who haven't logged in recently
.\users\users.ps1 -IncludeEntraID -ListUsers -LastLoginBefore (Get-Date).AddDays(-30)
```

#### `-FilterByRiskLevel` - Risk Level Filter
```powershell
# Critical risk users only
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore -FilterByRiskLevel "Critical"

# High risk users
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore -FilterByRiskLevel "High"

# Low risk users
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore -FilterByRiskLevel "Low"
```

#### `-ShowOnlyNoMFA` - MFA Filter
```powershell
# Show only users WITHOUT MFA
.\users\users.ps1 -IncludeEntraID -ListUsers -ShowOnlyNoMFA

# Critical: Privileged accounts without MFA
.\users\users.ps1 -IncludeEntraID -ListUsers -ShowOnlyNoMFA -ShowOnlyPrivileged
```

#### `-ShowOnlyPrivileged` - Privileged Filter
```powershell
# Show only privileged/admin accounts
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers -ShowOnlyPrivileged
```

#### `-ShowOnlyDisabled` - Disabled Account Filter
```powershell
# Show only disabled accounts
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers -ShowOnlyDisabled
```

#### `-ShowOnlyGuests` - Guest User Filter
```powershell
# Show only guest/external users
.\users\users.ps1 -IncludeEntraID -ListUsers -ShowOnlyGuests

# Guest users without MFA (security risk!)
.\users\users.ps1 -IncludeEntraID -ListUsers -ShowOnlyGuests -ShowOnlyNoMFA
```

#### `-InactiveDays` - Inactivity Filter
```powershell
# Users inactive for 30+ days
.\users\users.ps1 -IncludeEntraID -ListUsers -InactiveDays 30

# Users inactive for 90+ days (common threshold)
.\users\users.ps1 -IncludeEntraID -ListUsers -InactiveDays 90

# Users inactive for 180+ days (cleanup candidates)
.\users\users.ps1 -IncludeEntraID -ListUsers -InactiveDays 180
```

---

### Caching Parameters

#### `-UseCache` - Enable Caching
```powershell
# First run: fetches fresh data and caches it
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache

# Second run: uses cached data (much faster!)
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -FilterByDepartment "IT"
```

#### `-CacheExpiryMinutes` - Cache Duration
```powershell
# Cache expires after 30 minutes
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -CacheExpiryMinutes 30

# Cache expires after 2 hours (120 minutes)
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -CacheExpiryMinutes 120
```

#### `-ClearCache` - Clear Cached Data
```powershell
# Clear cache before running (force fresh data)
.\users\users.ps1 -IncludeEntraID -ListUsers -ClearCache
```

---

### Compliance Parameters

#### `-ComplianceFramework` - Generate Compliance Reports
```powershell
# SOX compliance report
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "SOX"

# HIPAA compliance report
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "HIPAA"

# GDPR compliance report
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "GDPR"

# PCI-DSS compliance report
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "PCI-DSS"

# ISO 27001 compliance report
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "ISO27001"

# NIST Cybersecurity Framework report
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "NIST"

# CIS Controls v8 report
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "CIS"

# All frameworks at once
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "All"

# Multiple specific frameworks
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "SOX","HIPAA","PCI-DSS"
```

---

### Utility Parameters

#### `-Help` - Display Help
```powershell
# Show help information
.\users\users.ps1 -Help
```

#### `-ConfigFile` - Use Configuration File
```powershell
# Load settings from JSON config file
.\users\users.ps1 -ConfigFile "C:\Config\audit-config.json"
```

#### `-Profile` - Use Predefined Profile
```powershell
# Quick profile (minimal data, fast)
.\users\users.ps1 -Profile Quick

# Comprehensive profile (all features)
.\users\users.ps1 -Profile Comprehensive

# Security profile (security-focused features)
.\users\users.ps1 -Profile Security
```

---

### Combined Feature Examples

#### Complete Security Audit
```powershell
# Everything security-related
.\users\users.ps1 -IncludeEntraID -IncludeAD -IncludeLocal -ListUsers `
    -IncludeRiskScore `
    -IncludePrivilegedAccounts `
    -IncludeServiceAccounts `
    -IncludeGuestUsers `
    -IncludePasswordPolicy `
    -IncludeAccountLockout `
    -IncludeDeviceCompliance `
    -IncludeConditionalAccess `
    -IncludeRiskySignins `
    -IncludeGroupMembership `
    -IncludeAppPermissions `
    -ExportExcel -ExcelPath "Complete_Security_Audit.xlsx" `
    -IncludeExportFormats
```

#### Privileged Account Deep Dive
```powershell
# Comprehensive privileged account analysis
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers `
    -ShowOnlyPrivileged `
    -IncludeRiskScore `
    -IncludePasswordPolicy `
    -IncludeAccountLockout `
    -IncludeGroupMembership `
    -IncludeConditionalAccess `
    -ComplianceFramework "SOX","ISO27001","CIS" `
    -OutputDirectory "C:\PrivilegedAccounts\$(Get-Date -Format 'yyyy-MM-dd')" `
    -ExportExcel -ExcelPath "Privileged_Accounts_Audit.xlsx" `
    -IncludeExportFormats
```

#### Guest User Security Review
```powershell
# Comprehensive guest user analysis
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -ShowOnlyGuests `
    -IncludeRiskScore `
    -IncludeGuestUsers `
    -IncludeConditionalAccess `
    -IncludeAppPermissions `
    -ComplianceFramework "GDPR","ISO27001" `
    -ExportExcel -ExcelPath "Guest_User_Review.xlsx"
```

#### Department Security Assessment
```powershell
# IT department comprehensive audit
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers `
    -FilterByDepartment "IT" `
    -IncludeRiskScore `
    -IncludePrivilegedAccounts `
    -IncludePasswordPolicy `
    -IncludeAccountLockout `
    -IncludeGroupMembership `
    -ComplianceFramework "All" `
    -OutputDirectory "C:\Reports\Departments\IT\$(Get-Date -Format 'yyyy-MM')" `
    -ExportExcel -ExcelPath "IT_Department_Audit.xlsx" `
    -IncludeExportFormats
```

#### Inactive Account Cleanup Campaign
```powershell
# Find all inactive accounts with full context
.\users\users.ps1 -IncludeEntraID -IncludeAD -IncludeLocal -ListUsers `
    -InactiveDays 90 `
    -IncludeRiskScore `
    -IncludePasswordPolicy `
    -IncludeGroupMembership `
    -ShowOnlyDisabled:$false `
    -OutputDirectory "C:\Cleanup\Inactive_$(Get-Date -Format 'yyyy-MM-dd')" `
    -ExportExcel -ExcelPath "Inactive_Accounts.xlsx" `
    -IncludeExportFormats
```

#### MFA Adoption Campaign
```powershell
# Find all users without MFA, prioritized by risk
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -ShowOnlyNoMFA `
    -IncludeRiskScore `
    -IncludePrivilegedAccounts `
    -IncludeConditionalAccess `
    -FilterByRiskLevel "Critical" `
    -OutputDirectory "C:\MFA_Campaign\$(Get-Date -Format 'yyyy-MM-dd')" `
    -ExportExcel -ExcelPath "NoMFA_Critical.xlsx"
```

#### Password Policy Enforcement
```powershell
# Find all password policy violations
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers `
    -IncludePasswordPolicy `
    -IncludeRiskScore `
    -ComplianceFramework "PCI-DSS","ISO27001" `
    -OutputDirectory "C:\PasswordAudit\$(Get-Date -Format 'yyyy-MM-dd')" `
    -ExportExcel -ExcelPath "Password_Policy_Audit.xlsx"
```

#### Cached Performance Testing
```powershell
# First: Load data and cache it
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -CacheExpiryMinutes 120

# Then: Run multiple queries using cached data (very fast!)
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -FilterByDepartment "Finance" -ExportExcel -ExcelPath "Finance.xlsx"
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -FilterByDepartment "IT" -ExportExcel -ExcelPath "IT.xlsx"
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -ShowOnlyPrivileged -ExportExcel -ExcelPath "Privileged.xlsx"
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -ShowOnlyNoMFA -ExportExcel -ExcelPath "NoMFA.xlsx"
```

#### Location-Based Audit
```powershell
# Audit all users in specific location with full security context
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -FilterByLocation "London" `
    -IncludeRiskScore `
    -IncludeDeviceCompliance `
    -IncludeConditionalAccess `
    -ComplianceFramework "GDPR","ISO27001" `
    -OutputDirectory "C:\Reports\Locations\London\$(Get-Date -Format 'yyyy-MM')" `
    -ExportExcel -ExcelPath "London_Office_Audit.xlsx" `
    -IncludeExportFormats
```

#### Date-Range Activity Report
```powershell
# Users who logged in during Q1 2025
.\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers `
    -LastLoginAfter "2025-01-01" `
    -LastLoginBefore "2025-03-31" `
    -IncludeRiskScore `
    -OutputDirectory "C:\Reports\Activity\2025-Q1" `
    -ExportExcel -ExcelPath "Q1_Activity.xlsx"
```

#### Minimal Quick Check
```powershell
# Quick overview with minimal columns (fast!)
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -Minimal `
    -MaxRecords 100 `
    -OutGridView
```

#### GUI Interactive Analysis
```powershell
# Open in GUI for interactive filtering
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -IncludeRiskScore `
    -IncludePrivilegedAccounts `
    -IncludePasswordPolicy `
    -IncludeGroupMembership `
    -OutGridView
```

---

## 🔧 Troubleshooting

### Issue: "PowerShell version is too old"

**Problem:** Script requires PowerShell 7+, you have 5.1 or older

**Solution:**
```powershell
# Download and install PowerShell 7
# Visit: https://github.com/PowerShell/PowerShell/releases

# Or use winget
winget install Microsoft.PowerShell

# Verify installation
pwsh -Version
```

---

### Issue: "ImportExcel module not found"

**Problem:** Excel export fails, falls back to CSV

**Solution:**
```powershell
# Install the ImportExcel module
Install-Module ImportExcel -Scope CurrentUser -Force

# Verify installation
Get-Module -ListAvailable ImportExcel
```

---

### Issue: "Unable to connect to Microsoft Graph"

**Problem:** Entra ID queries fail with authentication error

**Solution:**
```powershell
# Install Microsoft Graph module
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Try manual connection first
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All"

# Then run the script
.\users\users.ps1 -IncludeEntraID -ListUsers
```

---

### Issue: "Access Denied" for Active Directory

**Problem:** Cannot query AD, permission denied

**Solution:**
1. Ensure you're logged in with a domain account
2. Verify you have "Read" permissions to Active Directory
3. Run from a domain-joined machine
4. Try specifying a different DC:
```powershell
.\users\users.ps1 -IncludeAD -ListUsers -DomainController "DC01.domain.com"
```

---

### Issue: "No compliance worksheet in Excel"

**Problem:** Excel file created but missing compliance data

**Solution:**
Ensure you specify `-ComplianceFramework`:
```powershell
# Correct usage
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "SOX" -ExportExcel -ExcelPath ".\Report.xlsx"
```

---

### Issue: "Script runs very slowly"

**Problem:** Takes too long to fetch data

**Solutions:**
```powershell
# Use caching for repeated queries
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache

# Limit number of records
.\users\users.ps1 -IncludeEntraID -ListUsers -MaxRecords 100

# Query specific data sources only (not all)
.\users\users.ps1 -IncludeEntraID -ListUsers  # Not: -IncludeEntraID -IncludeAD -IncludeLocal
```

---

### Issue: "Cannot find compliance CSV file"

**Problem:** Compliance CSV not created

**Solution:**
Add `-IncludeExportFormats` parameter:
```powershell
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "All" -ExportExcel -ExcelPath ".\Report.xlsx" -IncludeExportFormats
```

---

### Issue: "MFA Status shows 'Error Retrieving'"

**Problem:** Cannot get MFA authentication methods

**Solution:**
```powershell
# Reconnect with proper scopes
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All"

# Then run the script
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeMFADetails
```

---

## 🚀 Advanced Topics

### Using Profiles for Quick Access

Create custom profile scripts:

```powershell
# Create profile for daily checks
function Daily-SecurityCheck {
    .\users\users.ps1 -IncludeEntraID -ListUsers `
        -UseCache `
        -FilterByRiskLevel "Critical" `
        -ExportExcel -ExcelPath ".\Daily_$(Get-Date -Format 'yyyy-MM-dd').xlsx"
}

# Create profile for compliance
function Compliance-Report {
    param([string]$Framework = "All")
    .\users\users.ps1 -IncludeEntraID -IncludeAD -ListUsers `
        -ComplianceFramework $Framework `
        -ExportExcel -ExcelPath ".\Compliance_$Framework_$(Get-Date -Format 'yyyy-MM-dd').xlsx" `
        -IncludeExportFormats
}

# Add to your PowerShell profile
# notepad $PROFILE
```

---

### Integrating with Monitoring Systems

Export to JSON for SIEM/monitoring tools:

```powershell
# Generate JSON for automation
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -IncludeRiskScore `
    -ExportExcel -ExcelPath ".\Report.xlsx" `
    -IncludeExportFormats

# Parse JSON and send alerts
$data = Get-Content "Users_List_*.json" | ConvertFrom-Json
$critical = $data.UserData | Where-Object { $_.RiskLevel -eq "Critical" }

if ($critical.Count -gt 0) {
    # Send to monitoring system
    Invoke-RestMethod -Uri "https://monitoring.company.com/api/alerts" `
        -Method Post `
        -Body ($critical | ConvertTo-Json) `
        -ContentType "application/json"
}
```

---

### Scheduling Regular Audits

Create scheduled tasks:

```powershell
# Weekly compliance report
$Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\ITAuditKit\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework 'All' -ExportExcel -ExcelPath 'C:\Reports\Weekly_Compliance.xlsx'"

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am

Register-ScheduledTask -TaskName "Weekly_Compliance_Report" -Action $Action -Trigger $Trigger -Description "Weekly compliance audit report"
```

---

### Custom Filtering Logic

Combine multiple filters:

```powershell
# Complex filter: IT department, privileged, no MFA, active in last 30 days
.\users\users.ps1 -IncludeEntraID -ListUsers `
    -FilterByDepartment "IT" `
    -ShowOnlyPrivileged `
    -ShowOnlyNoMFA `
    -LastLoginAfter (Get-Date).AddDays(-30) `
    -ExportExcel -ExcelPath ".\IT_Privileged_NoMFA_Active.xlsx"
```

---

### Performance Optimization

Best practices for large environments:

```powershell
# Use caching for repeated queries
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -CacheExpiryMinutes 120

# Process in batches
.\users\users.ps1 -IncludeEntraID -ListUsers -MaxRecords 500 -ExportExcel -ExcelPath ".\Batch1.xlsx"

# Target specific departments
$departments = @("IT", "Finance", "HR", "Sales")
foreach ($dept in $departments) {
    .\users\users.ps1 -IncludeEntraID -ListUsers -UseCache -FilterByDepartment $dept -ExportExcel -ExcelPath ".\$dept`_Report.xlsx"
}
```

---

## 📞 Support & Resources

### Getting Help

```powershell
# Get detailed help for the script
Get-Help .\users\users.ps1 -Full

# Get help for specific parameter
Get-Help .\users\users.ps1 -Parameter ComplianceFramework

# List all available parameters
Get-Help .\users\users.ps1 -Parameter *
```

---

## 📝 License

This project is licensed under the GNU GENERAL PUBLIC LICENSE Version 3 - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## 🎉 Quick Reference Card

### Most Common Commands

```powershell
# Basic user list
.\users\users.ps1 -IncludeEntraID -ListUsers

# With Excel export
.\users\users.ps1 -IncludeEntraID -ListUsers -ExportExcel -ExcelPath ".\Report.xlsx"

# Find users without MFA
.\users\users.ps1 -IncludeEntraID -ListUsers -ShowOnlyNoMFA

# Generate SOX compliance report
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "SOX" -ExportExcel -ExcelPath ".\SOX.xlsx"

# Find inactive accounts
.\users\users.ps1 -IncludeEntraID -ListUsers -InactiveDays 90

# High-risk accounts
.\users\users.ps1 -IncludeEntraID -ListUsers -IncludeRiskScore -FilterByRiskLevel "Critical"

# Department audit
.\users\users.ps1 -IncludeEntraID -ListUsers -FilterByDepartment "IT" -ExportExcel -ExcelPath ".\IT_Audit.xlsx"

# Complete audit package
.\users\users.ps1 -IncludeEntraID -ListUsers -ComplianceFramework "All" -ExportExcel -ExcelPath ".\Full_Audit.xlsx" -IncludeExportFormats

# Fast repeated queries
.\users\users.ps1 -IncludeEntraID -ListUsers -UseCache
```

---

**Version:** 1.5.0  
**Last Updated:** October 16, 2025  
**PowerShell Version Required:** 7.0+  
**Status:** Production Ready

---

For the most up-to-date information and additional examples, refer to the documentation files in the `users/` directory.

Happy Auditing! 🔒
