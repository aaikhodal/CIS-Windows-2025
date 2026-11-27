#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Configures all failed Registry-based CIS Benchmark recommendations (Administrative Templates & Firewall)
    into a specified Active Directory Group Policy Object using Set-GPRegistryValue.
.TARGET
    Microsoft Windows Server 2025 (CIS Level 1)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$GPOName = "CIS-WindowsServer2025-L1-Remediation"
)

$ErrorActionPreference = "Stop"

# Verify or create the target GPO
$GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if (-not $GPO) {
    Write-Host "Creating new GPO: '$GPOName'..." -ForegroundColor Cyan
    $GPO = New-GPO -Name $GPOName -Comment "CIS Windows Server 2025 Level 1 Failed Controls Remediation"
} else {
    Write-Host "Updating existing GPO: '$GPOName'..." -ForegroundColor Cyan
}

# Helper function to apply registry values cleanly
function Set-CISPolicy {
    param (
        [string]$ControlID,
        [string]$Description,
        [string]$Key,
        [string]$ValueName,
        [Microsoft.Win32.RegistryValueKind]$Type,
        $Value
    )
    Write-Host "[$ControlID] $Description" -ForegroundColor Green
    Set-GPRegistryValue -Name $GPOName -Key $Key -ValueName $ValueName -Type $Type -Value $Value | Out-Null
}

# ==============================================================================
# 1. COMPUTER CONFIGURATION - ADMINISTRATIVE TEMPLATES
# ==============================================================================

# 18.10.18.6 - Ensure 'Enable App Installer Microsoft Store Source Certificate Validation Bypass' is set to 'Disabled'
Set-CISPolicy -ControlID "18.10.18.6" `
    -Description "Disable App Installer Microsoft Store Source Certificate Validation Bypass" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" `
    -ValueName "EnableMSAppInstallerProtocol" `
    -Type DWord -Value 0

# Note: Specific registry value for 18.10.18.6 Store Source Certificate Validation Bypass
Set-CISPolicy -ControlID "18.10.18.6" `
    -Description "Disable BypassMSStoreCertificateValidation" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" `
    -ValueName "BypassMSStoreCertificateValidation" `
    -Type DWord -Value 0

# 18.10.29.2 - Ensure 'Do not apply the Mark of the Web tag to files copied from insecure sources' is set to 'Disabled'
Set-CISPolicy -ControlID "18.10.29.2" `
    -Description "Enable Mark of the Web (MOTW) tagging for insecure sources" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
    -ValueName "NoDataExecutionPrevention" `
    -Type DWord -Value 0

Set-CISPolicy -ControlID "18.10.29.2" `
    -Description "Disable DoNotAddZoneInformation" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
    -ValueName "DoNotAddZoneInformation" `
    -Type DWord -Value 0

# 18.10.4.2 - Ensure 'Not allow per-user unsigned packages to install by default' is set to 'Enabled'
Set-CISPolicy -ControlID "18.10.4.2" `
    -Description "Prevent per-user unsigned AppX packages from installing by default" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" `
    -ValueName "BlockNonAdminUserInstall" `
    -Type DWord -Value 1

# 18.10.43.11.1.1.2 - Ensure 'Configure Remote Encryption Protection Mode' (Brute-Force Protection) is set to 'Enabled: Audit' (1) or 'Block' (2)
Set-CISPolicy -ControlID "18.10.43.11.1.1.2" `
    -Description "Set Defender Brute-Force Protection Mode to Audit (1)" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" `
    -ValueName "BruteForceProtectionAggressiveness" `
    -Type DWord -Value 1

# 18.10.43.13.4 - Ensure 'Trigger a quick scan after X days without any scans' is set to 'Enabled: 7'
Set-CISPolicy -ControlID "18.10.43.13.4" `
    -Description "Trigger Defender quick scan after 7 days without scans" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
    -ValueName "QuickScanInterval" `
    -Type DWord -Value 7

# 18.10.93.4.1 - Ensure 'Manage preview builds' is set to 'Disabled'
Set-CISPolicy -ControlID "18.10.93.4.1" `
    -Description "Disable Windows Update Preview Builds" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
    -ValueName "ManagePreviewBuilds" `
    -Type DWord -Value 1

Set-CISPolicy -ControlID "18.10.93.4.1" `
    -Description "Set ManagePreviewBuildsPolicyValue to 0 (Disable)" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
    -ValueName "ManagePreviewBuildsPolicyValue" `
    -Type DWord -Value 0

# 18.6.7.5 - Ensure 'Enable remote mailslots' (LanmanServer) is set to 'Disabled' (Requires Reboot)
Set-CISPolicy -ControlID "18.6.7.5" `
    -Description "Disable SMB Server remote mailslots" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
    -ValueName "EnableMailslots" `
    -Type DWord -Value 0

# 18.6.7.7 - Ensure 'Set authentication rate limiter delay (milliseconds)' is set to 'Enabled: 2000' or more
Set-CISPolicy -ControlID "18.6.7.7" `
    -Description "Set SMB Server authentication rate limiter delay to 2000ms" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
    -ValueName "InvalidAuthenticationDelayTimeInMs" `
    -Type DWord -Value 2000

# 18.6.8.5 - Ensure 'Enable remote mailslots' (LanmanWorkstation) is set to 'Disabled' (Requires Reboot)
Set-CISPolicy -ControlID "18.6.8.5" `
    -Description "Disable SMB Workstation remote mailslots" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
    -ValueName "EnableMailslots" `
    -Type DWord -Value 0

# 18.9.39.3 - Ensure 'Configure SAM change password RPC methods policy' is set to 'Enabled: Block all change password RPC methods'
Set-CISPolicy -ControlID "18.9.39.3" `
    -Description "Block all SAM change password RPC methods" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\SAM" `
    -ValueName "SamChangePasswordRpcMethods" `
    -Type DWord -Value 1


# ==============================================================================
# 2. USER CONFIGURATION - ADMINISTRATIVE TEMPLATES
# ==============================================================================

# 19.5.1.1 - Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
Set-CISPolicy -ControlID "19.5.1.1" `
    -Description "Turn off toast notifications on the lock screen" `
    -Key "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" `
    -ValueName "NoToastApplicationNotificationOnLockScreen" `
    -Type DWord -Value 1

# 19.7.26.1 - Ensure 'Prevent users from sharing files within their profile' is set to 'Enabled'
Set-CISPolicy -ControlID "19.7.26.1" `
    -Description "Prevent users from sharing files within their profile" `
    -Key "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoInplaceSharing" `
    -Type DWord -Value 1

# 19.7.44.1 - Ensure 'Always install with elevated privileges' (User) is set to 'Disabled'
Set-CISPolicy -ControlID "19.7.44.1" `
    -Description "Disable AlwaysInstallElevated for User configuration" `
    -Key "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    -ValueName "AlwaysInstallElevated" `
    -Type DWord -Value 0

# 19.7.5.1 - Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
Set-CISPolicy -ControlID "19.7.5.1" `
    -Description "Preserve zone information in file attachments" `
    -Key "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
    -ValueName "SaveZoneInformation" `
    -Type DWord -Value 2

# 19.7.5.2 - Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
Set-CISPolicy -ControlID "19.7.5.2" `
    -Description "Notify antivirus programs when opening attachments" `
    -Key "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
    -ValueName "ScanWithAntiVirus" `
    -Type DWord -Value 3

# 19.7.8.1 - Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'
Set-CISPolicy -ControlID "19.7.8.1" `
    -Description "Disable Windows Spotlight on lock screen" `
    -Key "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
    -ValueName "ConfigureWindowsSpotlight" `
    -Type DWord -Value 2

# 19.7.8.2 - Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
Set-CISPolicy -ControlID "19.7.8.2" `
    -Description "Do not suggest third-party content in Windows Spotlight" `
    -Key "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
    -ValueName "DisableThirdPartySuggestions" `
    -Type DWord -Value 1

# 19.7.8.5 - Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'
Set-CISPolicy -ControlID "19.7.8.5" `
    -Description "Turn off Spotlight collection on Desktop" `
    -Key "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
    -ValueName "DisableSpotlightCollectionOnDesktop" `
    -Type DWord -Value 1


# ==============================================================================
# 3. WINDOWS DEFENDER FIREWALL WITH ADVANCED SECURITY (9.1.x, 9.2.x, 9.3.x)
# ==============================================================================

$FirewallBaseKey = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"

# --- 9.1.x Domain Profile ---
$DomainFW = "$FirewallBaseKey\DomainProfile"
Set-CISPolicy -ControlID "9.1.1" -Description "Domain Firewall State: On" -Key $DomainFW -ValueName "EnableFirewall" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.1.2" -Description "Domain Inbound Connections: Block" -Key $DomainFW -ValueName "DefaultInboundAction" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.1.3" -Description "Domain Display Notification: No" -Key $DomainFW -ValueName "DisableNotifications" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.1.4" -Description "Domain Log File Path" -Key "$DomainFW\Logging" -ValueName "LogFilePath" -Type ExpandString -Value "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
Set-CISPolicy -ControlID "9.1.5" -Description "Domain Log Size Limit: 16384 KB" -Key "$DomainFW\Logging" -ValueName "LogFileSize" -Type DWord -Value 16384
Set-CISPolicy -ControlID "9.1.6" -Description "Domain Log Dropped Packets: Yes" -Key "$DomainFW\Logging" -ValueName "LogDroppedPackets" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.1.7" -Description "Domain Log Successful Connections: Yes" -Key "$DomainFW\Logging" -ValueName "LogSuccessfulConnections" -Type DWord -Value 1


# --- 9.2.x Private Profile ---

$PrivateFW = "$FirewallBaseKey\PrivateProfile"
Set-CISPolicy -ControlID "9.2.1" -Description "Private Firewall State: On" -Key $PrivateFW -ValueName "EnableFirewall" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.2.2" -Description "Private Inbound Connections: Block" -Key $PrivateFW -ValueName "DefaultInboundAction" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.2.3" -Description "Private Display Notification: No" -Key $PrivateFW -ValueName "DisableNotifications" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.2.4" -Description "Private Log File Path" -Key "$PrivateFW\Logging" -ValueName "LogFilePath" -Type ExpandString -Value "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
Set-CISPolicy -ControlID "9.2.5" -Description "Private Log Size Limit: 16384 KB" -Key "$PrivateFW\Logging" -ValueName "LogFileSize" -Type DWord -Value 16384
Set-CISPolicy -ControlID "9.2.6" -Description "Private Log Dropped Packets: Yes" -Key "$PrivateFW\Logging" -ValueName "LogDroppedPackets" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.2.7" -Description "Private Log Successful Connections: Yes" -Key "$PrivateFW\Logging" -ValueName "LogSuccessfulConnections" -Type DWord -Value 1

# --- 9.3.x Public Profile ---

$PublicFW = "$FirewallBaseKey\PublicProfile"
Set-CISPolicy -ControlID "9.3.1" -Description "Public Firewall State: On" -Key $PublicFW -ValueName "EnableFirewall" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.3.2" -Description "Public Inbound Connections: Block" -Key $PublicFW -ValueName "DefaultInboundAction" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.3.3" -Description "Public Display Notification: No" -Key $PublicFW -ValueName "DisableNotifications" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.3.4" -Description "Public Apply Local Firewall Rules: No" -Key $PublicFW -ValueName "AllowLocalPolicyMerge" -Type DWord -Value 0
Set-CISPolicy -ControlID "9.3.5" -Description "Public Apply Local Connection Security Rules: No" -Key $PublicFW -ValueName "AllowLocalIPsecPolicyMerge" -Type DWord -Value 0
Set-CISPolicy -ControlID "9.3.6" -Description "Public Log File Path" -Key "$PublicFW\Logging" -ValueName "LogFilePath" -Type ExpandString -Value "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
Set-CISPolicy -ControlID "9.3.7" -Description "Public Log Size Limit: 16384 KB" -Key "$PublicFW\Logging" -ValueName "LogFileSize" -Type DWord -Value 16384
Set-CISPolicy -ControlID "9.3.8" -Description "Public Log Dropped Packets: Yes" -Key "$PublicFW\Logging" -ValueName "LogDroppedPackets" -Type DWord -Value 1
Set-CISPolicy -ControlID "9.3.9" -Description "Public Log Successful Connections: Yes" -Key "$PublicFW\Logging" -ValueName "LogSuccessfulConnections" -Type DWord -Value 1
Write-Host "`nAll registry-based GPO settings have been applied to '$GPOName'." -ForegroundColor Cyan
Write-Host "Next Steps: Link '$GPOName' to your target OU, verify firewall exceptions (e.g., RDP/WinRM) so you aren't locked out, and reboot the server for 18.6.7.5 & 18.6.8.5." -ForegroundColor Yellow