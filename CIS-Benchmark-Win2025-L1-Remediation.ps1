#Requires -Modules GroupPolicy
#Requires -RunAsAdministrator

$GPOName = "CIS-Benchmark-Win2025-L1-Remediation"

# 1. Create the GPO if it doesn't exist
if (-not (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue)) {
    New-GPO -Name $GPOName -Comment "Automated remediation for CIS Windows Server 2025 Level 1 Failed Findings" | Out-Null
    Write-Host "[+] Created GPO: $GPOName" -ForegroundColor Green
} else {
    Write-Host "[*] Using existing GPO: $GPOName" -ForegroundColor Yellow
}

# Helper function to set GPO Registry Values cleanly
function Set-CISRegistryPolicy {
    param(
        [string]$Key,
        [string]$ValueName,
        [Microsoft.Win32.RegistryValueKind]$Type,
        [object]$Value,
        [string]$RuleID
    )
    try {
        Set-GPRegistryValue -Name $GPOName -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop | Out-Null
        Write-Host "[OK] Remediated CIS $RuleID ($ValueName)" -ForegroundColor Cyan
    } catch {
        Write-Warning "[FAIL] Could not set CIS $RuleID ($ValueName): $_"
    }
}

# ==============================================================================
# SECTION 18: ADMINISTRATIVE TEMPLATES (COMPUTER CONFIGURATION)
# ==============================================================================

# 18.1.1.1 - Prevent enabling lock screen camera
Set-CISRegistryPolicy -RuleID "18.1.1.1" -Key "HKLM\Software\Policies\Microsoft\Windows\Personalization" -ValueName "NoLockScreenCamera" -Type DWord -Value 1

# 18.1.1.2 - Prevent enabling lock screen slide show
Set-CISRegistryPolicy -RuleID "18.1.1.2" -Key "HKLM\Software\Policies\Microsoft\Windows\Personalization" -ValueName "NoLockScreenSlideshow" -Type DWord -Value 1

# 18.1.2.2 - Allow users to enable online speech recognition services (Disabled)
Set-CISRegistryPolicy -RuleID "18.1.2.2" -Key "HKLM\Software\Policies\Microsoft\InputPersonalization" -ValueName "AllowInputPersonalization" -Type DWord -Value 0

# 18.4.2 - Configure SMB v1 client driver (Disable driver = 4)
Set-CISRegistryPolicy -RuleID "18.4.2" -Key "HKLM\System\CurrentControlSet\Services\mrxsmb10" -ValueName "Start" -Type DWord -Value 4

# 18.4.3 - Configure SMB v1 server (Disabled)
Set-CISRegistryPolicy -RuleID "18.4.3" -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Type DWord -Value 0

# 18.4.6 - NetBT NodeType configuration (P-node = 2)
Set-CISRegistryPolicy -RuleID "18.4.6" -Key "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NodeType" -Type DWord -Value 2

# 18.4.7 - WDigest Authentication (Disabled)
Set-CISRegistryPolicy -RuleID "18.4.7" -Key "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -Type DWord -Value 0

# 18.5.1 - MSS: (AutoAdminLogon) Enable Automatic Logon (Disabled)
Set-CISRegistryPolicy -RuleID "18.5.1" -Key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "AutoAdminLogon" -Type String -Value "0"

# 18.5.2 - MSS: (DisableIPSourceRouting IPv6) (Highest protection = 2)
Set-CISRegistryPolicy -RuleID "18.5.2" -Key "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" -ValueName "DisableIPSourceRouting" -Type DWord -Value 2

# 18.5.3 - MSS: (DisableIPSourceRouting) (Highest protection = 2)
Set-CISRegistryPolicy -RuleID "18.5.3" -Key "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "DisableIPSourceRouting" -Type DWord -Value 2

# 18.5.4 - MSS: (EnableICMPRedirect) (Disabled = 0)
Set-CISRegistryPolicy -RuleID "18.5.4" -Key "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "EnableICMPRedirect" -Type DWord -Value 0

# 18.5.6 - MSS: (NoNameReleaseOnDemand) (Enabled = 1)
Set-CISRegistryPolicy -RuleID "18.5.6" -Key "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NoNameReleaseOnDemand" -Type DWord -Value 1

# 18.5.8 - MSS: (SafeDllSearchMode) (Enabled = 1)
Set-CISRegistryPolicy -RuleID "18.5.8" -Key "HKLM\System\CurrentControlSet\Control\Session Manager" -ValueName "SafeDllSearchMode" -Type DWord -Value 1

# 18.5.9 - MSS: (ScreenSaverGracePeriod) (5 or fewer seconds)
Set-CISRegistryPolicy -RuleID "18.5.9" -Key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ScreenSaverGracePeriod" -Type String -Value "5"

# 18.5.12 - MSS: (WarningLevel) Percentage threshold for security event log (90% or less)
Set-CISRegistryPolicy -RuleID "18.5.12" -Key "HKLM\System\CurrentControlSet\Services\Eventlog\Security" -ValueName "WarningLevel" -Type DWord -Value 90

# 18.6.4.1 - Configure multicast DNS (mDNS) protocol (Disabled)
Set-CISRegistryPolicy -RuleID "18.6.4.1" -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMDNS" -Type DWord -Value 0

# 18.6.4.2 - Configure NetBIOS settings (Disable NetBIOS on public networks = 2)
Set-CISRegistryPolicy -RuleID "18.6.4.2" -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableNetbios" -Type DWord -Value 2

# 18.6.4.4 - Turn off multicast name resolution (LLMNR) (Enabled = 0)
Set-CISRegistryPolicy -RuleID "18.6.4.4" -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0

# 18.6.7.3 - 18.6.7.7 - Lanman Server (SMB Server)
Set-CISRegistryPolicy -RuleID "18.6.7.3" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanServer" -ValueName "AuditInsecureGuestLogon" -Type DWord -Value 1
Set-CISRegistryPolicy -RuleID "18.6.7.4" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanServer" -ValueName "EnableAuthRateLimiter" -Type DWord -Value 1
Set-CISRegistryPolicy -RuleID "18.6.7.5" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanServer" -ValueName "EnableMailslots" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.6.7.6" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanServer" -ValueName "MinSmb2Dialect" -Type DWord -Value 785 # 0x0311 (SMB 3.1.1)
Set-CISRegistryPolicy -RuleID "18.6.7.7" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanServer" -ValueName "AuthRateLimiterDelayInMs" -Type DWord -Value 2000

# 18.6.8.1 - 18.6.8.7 - Lanman Workstation (SMB Client)
Set-CISRegistryPolicy -RuleID "18.6.8.1" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "AuditInsecureGuestLogon" -Type DWord -Value 1
Set-CISRegistryPolicy -RuleID "18.6.8.2" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "AuditServerDoesNotSupportEncryption" -Type DWord -Value 1
Set-CISRegistryPolicy -RuleID "18.6.8.3" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "AuditServerDoesNotSupportSigning" -Type DWord -Value 1
Set-CISRegistryPolicy -RuleID "18.6.8.4" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "AllowInsecureGuestAuth" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.6.8.5" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "EnableMailslots" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.6.8.6" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "MinSmb2Dialect" -Type DWord -Value 785 # 0x0311 (SMB 3.1.1)
Set-CISRegistryPolicy -RuleID "18.6.8.7" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "RequireEncryption" -Type DWord -Value 1

# 18.6.11.2 - 18.6.11.4 - Network Connections
Set-CISRegistryPolicy -RuleID "18.6.11.2" -Key "HKLM\Software\Policies\Microsoft\Windows\Network Connections" -ValueName "NC_AllowNetBridge_NLA" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.6.11.3" -Key "HKLM\Software\Policies\Microsoft\Windows\Network Connections" -ValueName "NC_ShowSharedAccessUI" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.6.11.4" -Key "HKLM\Software\Policies\Microsoft\Windows\Network Connections" -ValueName "NC_StdDomainUserSetLocation" -Type DWord -Value 1

# 18.6.14.1 - Hardened UNC Paths
Set-CISRegistryPolicy -RuleID "18.6.14.1" -Key "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -ValueName "\\*\NETLOGON" -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
Set-CISRegistryPolicy -RuleID "18.6.14.1" -Key "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -ValueName "\\*\SYSVOL" -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"

# 18.6.21.1 - Minimize simultaneous connections (3 = Prevent Wi-Fi when on Ethernet)
Set-CISRegistryPolicy -RuleID "18.6.21.1" -Key "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -ValueName "fMinimizeConnections" -Type DWord -Value 3

# 18.7.2 - 18.7.13 - Printers & Print Spooler RPC
Set-CISRegistryPolicy -RuleID "18.7.2" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers" -ValueName "RedirectionguardPolicy" -Type DWord -Value 1
Set-CISRegistryPolicy -RuleID "18.7.3" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\RPC" -ValueName "RpcUseNamedPipeProtocol" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.7.4" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\RPC" -ValueName "RpcAuthentication" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.7.5" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\RPC" -ValueName "RpcProtocols" -Type DWord -Value 5
Set-CISRegistryPolicy -RuleID "18.7.6" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\RPC" -ValueName "ForceKerberosForRpc" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.7.7" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\RPC" -ValueName "RpcTcpPort" -Type DWord -Value 0
Set-CISRegistryPolicy -RuleID "18.7.8" -Key "HKLM\System\CurrentControlSet\Control\Print" -ValueName "RpcAuthnLevelPrivacyEnabled" -Type DWord -Value 1
Set-CISRegistryPolicy -RuleID "18.7.10" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "RestrictDriverInstallationToAdministrators" -Type DWord -Value 1
