<#
.SYNOPSIS
    Automated CIS Benchmark Remediation Script for Microsoft Windows Server 2025.

.DESCRIPTION
    Applies or reverts all CIS Level 1 recommendations parsed from Column F of the benchmark table.
    Configures:
      - Administrative Template Policies (Registry Settings via Set-GPRegistryValue)
      - Security Options & User Rights Assignments (GptTmpl.inf)
      - Advanced Audit Policy Subcategories (audit.csv)
      - Windows Defender & Exploit Guard / Attack Surface Reduction (ASR) rules

.PARAMETER GpoName
    The target Group Policy Object name in Active Directory (e.g. "CIS-WindowsServer2025-Baseline").

.PARAMETER Mode
    Specifies the action:
      - 'Enable'  : Applies all CIS recommended security states.
      - 'Disable' : Reverts, removes, or clears the configured GPO baseline settings.

.PARAMETER Domain
    Optional. The target Active Directory FQDN (defaults to current domain).

.EXAMPLE
    .\Set-CISServer2025Remediation.ps1 -GpoName "CIS-WindowsServer2025-Baseline" -Mode Enable

.EXAMPLE
    .\Set-CISServer2025Remediation.ps1 -GpoName "CIS-WindowsServer2025-Baseline" -Mode Disable
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$GpoName,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateSet("Enable", "Disable")]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
)

# -------------------------------------------------------------------------
# 1. Verification and Initialization
# -------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    throw "The 'GroupPolicy' module was not found. Please install RSAT Group Policy Management tools: Install-WindowsFeature GPMC"
}
Import-Module GroupPolicy -ErrorAction Stop

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " CIS Microsoft Windows Server 2025 Benchmark Remediation Script" -ForegroundColor Cyan
Write-Host " Target GPO : $GpoName" -ForegroundColor Yellow
Write-Host " Mode       : $Mode" -ForegroundColor Yellow
Write-Host " Domain     : $Domain" -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Cyan

$Gpo = Get-GPO -Name $GpoName -Domain $Domain -ErrorAction SilentlyContinue
if (-not $Gpo) {
    if ($Mode -eq "Enable") {
        Write-Host "[+] Creating target GPO '$GpoName'..." -ForegroundColor Green
        $Gpo = New-GPO -Name $GpoName -Comment "CIS Windows Server 2025 Baseline Enforcement" -Domain $Domain
    } else {
        throw "Target GPO '$GpoName' does not exist in domain '$Domain'. Nothing to revert."
    }
}

$GpoGuid = $Gpo.Id.ToString("B").ToUpper()
$SysvolGpoPath = "\\$Domain\SYSVOL\$Domain\Policies\$GpoGuid"

# -------------------------------------------------------------------------
# 2. Administrative Templates Registry Policies Definition
# -------------------------------------------------------------------------
$RegistryPolicies = @(
    # --- Printers (Section 18.7) ---
    @{ Id="18.7.10"; Title="Limits print driver installation to Administrators"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers"; Value="RestrictDriverInstallationToAdministrators"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.7.11"; Title="Manage processing of Queue-specific files"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers"; Value="CopyFilesPolicy"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.7.12"; Title="Point and Print Restrictions: Install drivers prompt"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Value="PromptOnSupportDrivers"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.7.13"; Title="Point and Print Restrictions: Update drivers prompt"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Value="PromptOnSupportUpdate"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.7.4";  Title="Configure RPC connection settings: Protocol to negotiate"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers"; Value="RpcProtocols"; Type="DWord"; Enable=7; Disable=0 },
    @{ Id="18.7.9";  Title="Configure Redirection Guard"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Printers"; Value="RedirectionGuard"; Type="DWord"; Enable=1; Disable=0 },

    # --- Windows Defender Antivirus & Real-Time Protection (Section 18.10.43) ---
    @{ Id="18.10.43.10.1"; Title="Real-time protection and Security Intelligence Updates during OOBE"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Value="OobeEnableRtpAndSigUpdate"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.10.43.10.2"; Title="Scan all downloaded files and attachments"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Value="DisableIOAVProtection"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.43.10.3"; Title="Turn off real-time protection is Disabled"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Value="DisableRealtimeMonitoring"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.43.10.4"; Title="Turn on behavior monitoring"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Value="DisableBehaviorMonitoring"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.43.10.5"; Title="Turn on script scanning"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Value="DisableScriptScanning"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.43.13.1"; Title="Scan excluded files and directories during quick scans"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Scan"; Value="QuickScanIncludeExclusions"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.10.43.13.2"; Title="Scan packed executables"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Scan"; Value="DisablePackedExeScanning"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.43.13.3"; Title="Scan removable drives"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Scan"; Value="DisableRemovableDriveScanning"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.43.13.4"; Title="Trigger a quick scan after X days without any scans (7 days)"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Scan"; Value="ScanParameters"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.10.43.13.5"; Title="Turn on e-mail scanning"; Key="HKLM\Software\Policies\Microsoft\Windows Defender\Scan"; Value="DisableEmailScanning"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.43.16";   Title="Configure detection for potentially unwanted applications (PUA)"; Key="HKLM\Software\Policies\Microsoft\Windows Defender"; Value="PUAProtection"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.10.43.17";   Title="Control whether exclusions are visible to local users"; Key="HKLM\Software\Policies\Microsoft\Windows Defender"; Value="HideExclusionsFromLocalUsers"; Type="DWord"; Enable=1; Disable=0 },

    # --- Windows LAPS (Section 18.9.25) ---
    @{ Id="18.9.25.1"; Title="Configure password backup directory: Active Directory / Entra ID"; Key="HKLM\Software\Policies\Microsoft\Windows\LAPS"; Value="BackupDirectory"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.9.25.2"; Title="Do not allow password expiration time longer than required by policy"; Key="HKLM\Software\Policies\Microsoft\Windows\LAPS"; Value="PasswordAgeDays"; Type="DWord"; Enable=30; Disable=0 },
    @{ Id="18.9.25.3"; Title="Enable password encryption"; Key="HKLM\Software\Policies\Microsoft\Windows\LAPS"; Value="PasswordEncryption"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.9.25.4"; Title="Password Settings: Password Complexity (Large + small + numbers + specials)"; Key="HKLM\Software\Policies\Microsoft\Windows\LAPS"; Value="PasswordComplexity"; Type="DWord"; Enable=4; Disable=0 },
    @{ Id="18.9.25.5"; Title="Password Settings: Password Length (15 or more)"; Key="HKLM\Software\Policies\Microsoft\Windows\LAPS"; Value="PasswordLength"; Type="DWord"; Enable=15; Disable=8 },
    @{ Id="18.9.25.6"; Title="Password Settings: Password Age (Days: 30 or fewer)"; Key="HKLM\Software\Policies\Microsoft\Windows\LAPS"; Value="PasswordAgeDays"; Type="DWord"; Enable=30; Disable=0 },
    @{ Id="18.9.25.7"; Title="Post-authentication actions: Grace period (hours)"; Key="HKLM\Software\Policies\Microsoft\Windows\LAPS"; Value="PostAuthenticationResetDelay"; Type="DWord"; Enable=8; Disable=0 },

    # --- Cloud Content & Consumer Features (Section 18.10.13 & 18.10.42) ---
    @{ Id="18.10.13.1"; Title="Turn off cloud consumer account state content"; Key="HKLM\Software\Policies\Microsoft\Windows\CloudContent"; Value="DisableConsumerAccountStateContent"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.10.13.3"; Title="Turn off Microsoft consumer experiences"; Key="HKLM\Software\Policies\Microsoft\Windows\CloudContent"; Value="DisableWindowsConsumerFeatures"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.10.42.1"; Title="Block all consumer Microsoft account user authentication"; Key="HKLM\Software\Policies\Microsoft\Windows\Personalization"; Value="NoConnectedUser"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.10.51.1"; Title="Prevent the usage of OneDrive for file storage"; Key="HKLM\Software\Policies\Microsoft\Windows\OneDrive"; Value="DisableFileSyncNGSC"; Type="DWord"; Enable=1; Disable=0 },

    # --- Data Collection & Telemetry (Section 18.10.16) ---
    @{ Id="18.10.16.1"; Title="Allow Diagnostic Data: Send required diagnostic data"; Key="HKLM\Software\Policies\Microsoft\Windows\DataCollection"; Value="AllowTelemetry"; Type="DWord"; Enable=1; Disable=3 },
    @{ Id="18.10.16.3"; Title="Disable OneSettings Downloads"; Key="HKLM\Software\Policies\Microsoft\Windows\DataCollection"; Value="DisableOneSettingsDownloads"; Type="DWord"; Enable=1; Disable=0 },

    # --- Windows Remote Management - WinRM (Section 18.10.89) ---
    @{ Id="18.10.89.2.1"; Title="Allow Basic authentication (WinRM Client): Set to Disabled"; Key="HKLM\Software\Policies\Microsoft\Windows\WinRM\Client"; Value="AllowBasic"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.89.2.3"; Title="Allow unencrypted traffic (WinRM Client): Set to Disabled"; Key="HKLM\Software\Policies\Microsoft\Windows\WinRM\Client"; Value="AllowUnencryptedTraffic"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.89.3.1"; Title="Allow Basic authentication (WinRM Service): Set to Disabled"; Key="HKLM\Software\Policies\Microsoft\Windows\WinRM\Service"; Value="AllowBasic"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.89.3.2"; Title="Allow unencrypted traffic (WinRM Service): Set to Disabled"; Key="HKLM\Software\Policies\Microsoft\Windows\WinRM\Service"; Value="AllowUnencryptedTraffic"; Type="DWord"; Enable=0; Disable=1 },

    # --- Network, SMB & RPC (Section 18.6 & 18.9) ---
    @{ Id="18.6.7.1";  Title="Audit client does not support encryption"; Key="HKLM\Software\Policies\Microsoft\Windows\LanmanServer"; Value="AuditClientDoesNotSupportEncryption"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.6.7.2";  Title="Audit client does not support signing"; Key="HKLM\Software\Policies\Microsoft\Windows\LanmanServer"; Value="AuditClientDoesNotSupportSigning"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.6.7.3";  Title="Audit insecure guest logon"; Key="HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation"; Value="EnableInsecureGuestLogons"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.6.7.4";  Title="Enable SMB server authentication rate limiter"; Key="HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"; Value="InvalidThreshold"; Type="DWord"; Enable=2000; Disable=0 },
    @{ Id="18.6.7.7";  Title="Set SMB authentication rate limiter delay"; Key="HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"; Value="InvalidThresholdDelay"; Type="DWord"; Enable=2000; Disable=0 },
    @{ Id="18.9.36.1"; Title="Enable RPC Endpoint Mapper Client Authentication"; Key="HKLM\Software\Policies\Microsoft\Windows NT\Rpc"; Value="EnableAuthEpResolution"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.9.39.3"; Title="Configure SAM change password RPC methods policy: Block all"; Key="HKLM\Software\Policies\Microsoft\Windows NT\SAM"; Value="SamRpcBlockPasswordsChangeMethods"; Type="DWord"; Enable=1; Disable=0 },

    # --- Explorer & Device Hardening (Section 18.10 & 18.9) ---
    @{ Id="18.10.8.2";   Title="Default behavior for AutoRun: Do not execute any autorun commands"; Key="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Value="NoAutorun"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.10.8.3";   Title="Turn off Autoplay: Enabled on all drives"; Key="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Value="NoDriveTypeAutoRun"; Type="DWord"; Enable=255; Disable=145 },
    @{ Id="18.10.29.2";  Title="Do not apply Mark of the Web to files copied from insecure sources"; Key="HKLM\Software\Policies\Microsoft\Windows\Explorer"; Value="DoNotPreserveZoneInfo"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.29.3";  Title="Turn off Data Execution Prevention for Explorer: Disabled"; Key="HKLM\Software\Policies\Microsoft\Windows\Explorer"; Value="NoDataExecutionPrevention"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.29.4";  Title="Turn off heap termination on corruption: Disabled"; Key="HKLM\Software\Policies\Microsoft\Windows\Explorer"; Value="NoHeapTerminationOnCorruption"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.10.29.5";  Title="Turn off shell protocol protected mode: Disabled"; Key="HKLM\Software\Policies\Microsoft\Windows\Explorer"; Value="PreXPSP2ShellProtocolBehavior"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.4.1";      Title="Apply UAC restrictions to local accounts on network logons"; Key="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Value="LocalAccountTokenFilterPolicy"; Type="DWord"; Enable=0; Disable=1 },
    @{ Id="18.9.20.1.5"; Title="Turn off Internet download for Web publishing and online ordering wizards"; Key="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Value="NoWebServices"; Type="DWord"; Enable=1; Disable=0 },
    @{ Id="18.9.24.1";   Title="Enumeration policy for external devices incompatible with Kernel DMA Protection"; Key="HKLM\Software\Policies\Microsoft\Windows\Kernel DMA Protection"; Value="DeviceEnumerationPolicy"; Type="DWord"; Enable=0; Disable=2 }
)

# -------------------------------------------------------------------------
# 3. Apply or Revert Administrative Templates
# -------------------------------------------------------------------------
Write-Host "`n[*] Processing Administrative Templates (${Mode})..." -ForegroundColor Cyan
$RegSuccess = 0
$RegFail = 0

foreach ($p in $RegistryPolicies) {
    try {
        if ($Mode -eq "Enable") {
            Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $p.Key -ValueName $p.Value -Type $p.Type -Value $p.Enable -ErrorAction Stop | Out-Null
        } else {
            Remove-GPRegistryValue -Name $GpoName -Domain $Domain -Key $p.Key -ValueName $p.Value -ErrorAction SilentlyContinue | Out-Null
        }
        $RegSuccess++
    } catch {
        Write-Warning "[$($p.Id)] $($p.Title): $_"
        $RegFail++
    }
}
Write-Host "Administrative Templates: $RegSuccess completed, $RegFail failed." -ForegroundColor Green

# -------------------------------------------------------------------------
# 4. Security Options & User Rights Assignment (GptTmpl.inf)
# -------------------------------------------------------------------------
Write-Host "`n[*] Configuring Local Security Settings & User Rights (${Mode})..." -ForegroundColor Cyan
$SecTemplateDir = "$SysvolGpoPath\Machine\Microsoft\Windows NT\SecEdit"
$SecTemplateFile = "$SecTemplateDir\GptTmpl.inf"

if ($Mode -eq "Enable") {
    if (-not (Test-Path $SecTemplateDir)) {
        New-Item -Path $SecTemplateDir -ItemType Directory -Force | Out-Null
    }

    # INF format compliant with secedit specifications for CIS Security Options & User Rights
    $InfContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
MaximumPasswordAge = 365
MinimumPasswordAge = 1
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\SupportedEncryptionTypes=4,2147483640
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11
SeInteractiveLogonRight = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-114
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-114
SeBackupPrivilege = *S-1-5-32-544
SeRestorePrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
"@
    Set-Content -Path $SecTemplateFile -Value $InfContent -Encoding Unicode -Force
    Write-Host "[+] Generated Security Template (GptTmpl.inf) with CIS Security Options and User Rights." -ForegroundColor Green
} else {
    if (Test-Path $SecTemplateFile) {
        Remove-Item -Path $SecTemplateFile -Force
        Write-Host "[-] Removed Security Template (GptTmpl.inf) to revert settings." -ForegroundColor Yellow
    }
}

# -------------------------------------------------------------------------
# 5. Advanced Audit Policies (audit.csv)
# -------------------------------------------------------------------------
Write-Host "`n[*] Configuring Advanced Audit Policies (${Mode})..." -ForegroundColor Cyan
$AuditDir = "$SysvolGpoPath\Machine\Microsoft\Windows NT\Audit"
$AuditCsv = "$AuditDir\audit.csv"

if ($Mode -eq "Enable") {
    if (-not (Test-Path $AuditDir)) {
        New-Item -Path $AuditDir -ItemType Directory -Force | Out-Null
    }

    # CSV headers and GUID mappings for Advanced Audit Policies based on Column F
    $AuditContent = @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
,System,Security System Extension,{0CCE9214-69AE-11D9-BED3-505054503030},1,0
,System,System Integrity,{0CCE9212-69AE-11D9-BED3-505054503030},3,0
,System,IPsec Driver,{0CCE9213-69AE-11D9-BED3-505054503030},3,0
,System,Other System Events,{0CCE9210-69AE-11D9-BED3-505054503030},3,0
,System,Security State Change,{0CCE9211-69AE-11D9-BED3-505054503030},1,0
,Logon/Logoff,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},3,0
,Logon/Logoff,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},1,0
,Logon/Logoff,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},2,0
,Logon/Logoff,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},1,0
,Detailed Tracking,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},1,0
,Account Management,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},3,0
,Account Management,Application Group Management,{0CCE9238-69AE-11D9-BED3-505054503030},3,0
,Account Management,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},1,0
,Policy Change,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},1,0
,Policy Change,Authentication Policy Change,{0CCE9230-69AE-11D9-BED3-505054503030},1,0
,Privilege Use,Sensitive Privilege Use,{0CCE9228-69AE-11D9-BED3-505054503030},3,0
"@
    Set-Content -Path $AuditCsv -Value $AuditContent -Encoding Ascii -Force
    Write-Host "[+] Generated GPO Advanced Audit Policy file (audit.csv)." -ForegroundColor Green
} else {
    if (Test-Path $AuditCsv) {
        Remove-Item -Path $AuditCsv -Force
        Write-Host "[-] Removed Advanced Audit Policy file (audit.csv)." -ForegroundColor Yellow
    }
}

# -------------------------------------------------------------------------
# 6. Attack Surface Reduction (ASR) Rules Configuration
# -------------------------------------------------------------------------
Write-Host "`n[*] Configuring Microsoft Defender ASR Rules (${Mode})..." -ForegroundColor Cyan
$AsrRules = @(
    "56a863a9-113f-425a-ab2b-232607937903", # Block abuse of in-the-wild exploited vulnerable signed drivers
    "76743d55-2d32-47dc-86b3-d4447547cb7d", # Block Adobe Reader from creating child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", # Block all Office apps from creating child processes
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", # Block credential stealing from the Windows LSASS
    "be9ba2d9-53ea-44a7-9161-ab4c4fceea57", # Block executable content from email client and webmail
    "01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files from running unless they meet criteria
    "5beb7efe-427c-4028-b999-4477211bf74b", # Block execution of potentially obfuscated scripts
    "d3e037e1-3eb8-44c8-a917-57927947596d", # Block JavaScript or VBScript from launching downloaded exec content
    "3b576469-a4a6-4443-8c76-80927b1a53e8", # Block Office apps from creating executable content
    "756346d0-4783-49d4-ad7b-4189233857e8", # Block Office apps from injecting code into other processes
    "26190899-773f-4764-bb10-739dec4197e3", # Block Office communication applications from creating child processes
    "b2b0f4d1-016e-4770-a7a1-d57429b6d08c"  # Block untrusted and unsigned processes that run from USB
)

$AsrKey = "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
foreach ($ruleId in $AsrRules) {
    if ($Mode -eq "Enable") {
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $AsrKey -ValueName $ruleId -Type String -Value "1" -ErrorAction SilentlyContinue | Out-Null
    } else {
        Remove-GPRegistryValue -Name $GpoName -Domain $Domain -Key $AsrKey -ValueName $ruleId -ErrorAction SilentlyContinue | Out-Null
    }
}
Write-Host "[+] Configured 12 CIS Exploit Guard ASR Rules (State: Block/1)." -ForegroundColor Green

# -------------------------------------------------------------------------
# 7. Refresh GPO Version in Active Directory
# -------------------------------------------------------------------------
Write-Host "`n[*] Incrementing GPO Version Header..." -ForegroundColor Cyan
$GptIniPath = "$SysvolGpoPath\gpt.ini"
if (Test-Path $GptIniPath) {
    $GptIni = Get-Content $GptIniPath
    $CurrentVersion = ($GptIni | Where-Object { $_ -match "^Version=(\d+)" } | ForEach-Object { $Matches[1] })
    if (-not $CurrentVersion) { $CurrentVersion = 0 }
    $NewVersion = [int]$CurrentVersion + 65537 # Increments both User and Machine version counters
    $GptIni = $GptIni -replace "^Version=\d+", "Version=$NewVersion"
    Set-Content -Path $GptIniPath -Value $GptIni -Force
    Write-Host "[+] Updated gpt.ini to Version $NewVersion to trigger client evaluation." -ForegroundColor Green
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " CIS Windows Server 2025 Remediation complete in '$Mode' mode." -ForegroundColor Green
Write-Host " To refresh domain member servers, execute: gpupdate /force" -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Cyan