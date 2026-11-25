#Requires -Modules GroupPolicy
#Requires -RunAsAdministrator

$GPOName = "CIS-Win2025-L1-18.9.3.1-to-End"

if (-not (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue)) {
    New-GPO -Name $GPOName -Comment "CIS Windows Server 2025 L1 Remediation (18.9.3.1 through 9.3.9)" | Out-Null
    Write-Host "[+] Created GPO: $GPOName" -ForegroundColor Green
} else {
    Write-Host "[*] Updating existing GPO: $GPOName" -ForegroundColor Yellow
}

function Set-CISReg {
    param(
        [string]$RuleID,
        [string]$Key,
        [string]$ValueName,
        [Microsoft.Win32.RegistryValueKind]$Type,
        [object]$Value
    )
    try {
        Set-GPRegistryValue -Name $GPOName -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop | Out-Null
        Write-Host "[OK] CIS $RuleID -> $ValueName" -ForegroundColor Cyan
    } catch {
        Write-Warning "[FAIL] CIS $RuleID ($ValueName): $_"
    }
}

# ==============================================================================
# PART 1: COMPUTER CONFIGURATION - ADMINISTRATIVE TEMPLATES (18.9.3.1 - 18.9.7.2)
# ==============================================================================

# 18.9.3.1 - Include command line in process creation events (Enabled)
Set-CISReg -RuleID "18.9.3.1" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1

# 18.9.30.1.1 - Block NetBIOS-based discovery for domain controller location (Enabled)
Set-CISReg -RuleID "18.9.30.1.1" -Key "HKLM\Software\Policies\Microsoft\Netlogon\Parameters" -ValueName "BlockNetbiosDiscovery" -Type DWord -Value 1

# 18.9.33.6.3 - Require a password when a computer wakes (on battery) (Enabled)
Set-CISReg -RuleID "18.9.33.6.3" -Key "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -ValueName "DCSettingIndex" -Type DWord -Value 1

# 18.9.33.6.4 - Require a password when a computer wakes (plugged in) (Enabled)
Set-CISReg -RuleID "18.9.33.6.4" -Key "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -ValueName "ACSettingIndex" -Type DWord -Value 1

# 18.9.35.1 - Configure Offer Remote Assistance (Disabled)
Set-CISReg -RuleID "18.9.35.1" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fAllowUnsolicited" -Type DWord -Value 0

# 18.9.35.2 - Configure Solicited Remote Assistance (Disabled)
Set-CISReg -RuleID "18.9.35.2" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fAllowToGetHelp" -Type DWord -Value 0

# 18.9.39.3 - Configure SAM change password RPC methods policy (Enabled: Block all = 1)
Set-CISReg -RuleID "18.9.39.3" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\SAM" -ValueName "SamChangePasswordRpcMethods" -Type DWord -Value 1

# 18.9.4.1 - Encryption Oracle Remediation (Enabled: Force Updated Clients = 0)
Set-CISReg -RuleID "18.9.4.1" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -ValueName "AllowEncryptionOracle" -Type DWord -Value 0

# 18.9.4.2 - Remote host allows delegation of non-exportable credentials (Enabled)
Set-CISReg -RuleID "18.9.4.2" -Key "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" -ValueName "AllowProtectedCreds" -Type DWord -Value 1

# 18.9.51.1.1 - Enable Windows NTP Client (Enabled)
Set-CISReg -RuleID "18.9.51.1.1" -Key "HKLM\Software\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -ValueName "Enabled" -Type DWord -Value 1

# 18.9.51.1.2 - Enable Windows NTP Server (Disabled)
Set-CISReg -RuleID "18.9.51.1.2" -Key "HKLM\Software\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -ValueName "Enabled" -Type DWord -Value 0

# 18.9.7.2 - Prevent device metadata retrieval from the Internet (Enabled)
Set-CISReg -RuleID "18.9.7.2" -Key "HKLM\Software\Policies\Microsoft\Windows\Device Metadata" -ValueName "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1

# ==============================================================================
# PART 2: USER CONFIGURATION - ADMINISTRATIVE TEMPLATES (19.5.1.1 - 19.7.8.5)
# ==============================================================================

# 19.5.1.1 - Turn off toast notifications on the lock screen (Enabled)
Set-CISReg -RuleID "19.5.1.1" -Key "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ValueName "NoToastApplicationNotificationOnLockScreen" -Type DWord -Value 1

# 19.7.26.1 - Prevent users from sharing files within their profile (Enabled)
Set-CISReg -RuleID "19.7.26.1" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoInplaceSharing" -Type DWord -Value 1

# 19.7.44.1 - Always install with elevated privileges (Disabled)
Set-CISReg -RuleID "19.7.44.1" -Key "HKCU\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWord -Value 0

# 19.7.5.1 - Do not preserve zone information in file attachments (Disabled = 2)
Set-CISReg -RuleID "19.7.5.1" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "SaveZoneInformation" -Type DWord -Value 2

# 19.7.5.2 - Notify antivirus programs when opening attachments (Enabled = 3)
Set-CISReg -RuleID "19.7.5.2" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "ScanWithAntiVirus" -Type DWord -Value 3

# 19.7.8.1 - Configure Windows spotlight on lock screen (Disabled = 2)
Set-CISReg -RuleID "19.7.8.1" -Key "HKCU\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "ConfigureWindowsSpotlight" -Type DWord -Value 2

# 19.7.8.2 - Do not suggest third-party content in Windows spotlight (Enabled)
Set-CISReg -RuleID "19.7.8.2" -Key "HKCU\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableThirdPartySuggestions" -Type DWord -Value 1

# 19.7.8.5 - Turn off Spotlight collection on Desktop (Enabled)
Set-CISReg -RuleID "19.7.8.5" -Key "HKCU\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableSpotlightCollectionOnDesktop" -Type DWord -Value 1

# ==============================================================================
# PART 3: SECURITY OPTIONS - REGISTRY BACKED (2.3.2.1 - 2.3.17.3)
# ==============================================================================

# 2.3.2.1 - Audit: Force audit policy subcategory settings to override category settings (Enabled)
Set-CISReg -RuleID "2.3.2.1" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "SCENoApplyLegacyAuditPolicy" -Type DWord -Value 1

# 2.3.7.2 - Interactive logon: Don't display last signed-in (Enabled)
Set-CISReg -RuleID "2.3.7.2" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DontDisplayLastUserName" -Type DWord -Value 1

# 2.3.7.3 - Interactive logon: Machine inactivity limit (900 seconds)
Set-CISReg -RuleID "2.3.7.3" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "InactivityTimeoutSecs" -Type DWord -Value 900

# 2.3.7.4 - Interactive logon: Message text for users attempting to log on
Set-CISReg -RuleID "2.3.7.4" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "LegalNoticeText" -Type String -Value "Authorized users only. All activity may be monitored and reported."

# 2.3.7.5 - Interactive logon: Message title for users attempting to log on
Set-CISReg -RuleID "2.3.7.5" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "LegalNoticeCaption" -Type String -Value "Security Notice"

# 2.3.7.8 - Interactive logon: Require Domain Controller Authentication to unlock workstation (Enabled)
Set-CISReg -RuleID "2.3.7.8" -Key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ForceUnlockLogon" -Type DWord -Value 1

# 2.3.7.9 - Interactive logon: Smart card removal behavior (Lock Workstation = "1")
Set-CISReg -RuleID "2.3.7.9" -Key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ScRemoveOption" -Type String -Value "1"

# 2.3.8.1 - Microsoft network client: Digitally sign communications (always) (Enabled)
Set-CISReg -RuleID "2.3.8.1" -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1

# 2.3.9.2 - Microsoft network server: Digitally sign communications (always) (Enabled)
Set-CISReg -RuleID "2.3.9.2" -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1

# 2.3.9.3 - Microsoft network server: Digitally sign communications (if client agrees) (Enabled)
Set-CISReg -RuleID "2.3.9.3" -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "EnableSecuritySignature" -Type DWord -Value 1

# 2.3.9.5 - Microsoft network server: Server SPN target name validation level (Accept if provided by client = 1)
Set-CISReg -RuleID "2.3.9.5" -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SmbServerNameHardeningLevel" -Type DWord -Value 1

# 2.3.10.3 - Network access: Do not allow anonymous enumeration of SAM accounts and shares (Enabled)
Set-CISReg -RuleID "2.3.10.3" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymous" -Type DWord -Value 1

# 2.3.10.11 - Network access: Restrict clients allowed to make remote calls to SAM
Set-CISReg -RuleID "2.3.10.11" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "RestrictRemoteSAM" -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)"

# 2.3.11.1 - Network security: Allow Local System to use computer identity for NTLM (Enabled)
Set-CISReg -RuleID "2.3.11.1" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "UseMachineId" -Type DWord -Value 1

# 2.3.11.2 - Network security: Allow LocalSystem NULL session fallback (Disabled)

# 2.3.11.3 - Network Security: Allow PKU2U authentication requests to use online identities (Disabled)
Set-CISReg -RuleID "2.3.11.3" -Key "HKLM\System\CurrentControlSet\Control\Lsa\pku2u" -ValueName "AllowOnlineID" -Type DWord -Value 0

# 2.3.11.4 - Network security: Configure encryption types allowed for Kerberos (AES128, AES256, Future)
Set-CISReg -RuleID "2.3.11.4" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ValueName "SupportedEncryptionTypes" -Type DWord -Value 2147483640

# 2.3.11.7 - Network security: LAN Manager authentication level (Send NTLMv2 response only. Refuse LM & NTLM = 5)
Set-CISReg -RuleID "2.3.11.7" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Type DWord -Value 5

# 2.3.11.10 - Network security: Minimum session security for NTLM SSP clients (Require NTLMv2 + 128-bit)
Set-CISReg -RuleID "2.3.11.10" -Key "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "NTLMMinClientSec" -Type DWord -Value 537395200

# 2.3.11.11 - Network security: Minimum session security for NTLM SSP servers (Require NTLMv2 + 128-bit)
Set-CISReg -RuleID "2.3.11.11" -Key "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "NTLMMinServerSec" -Type DWord -Value 537395200

# 2.3.11.12 - Network security: Restrict NTLM: Audit Incoming NTLM Traffic (Enable auditing for all accounts = 2)
Set-CISReg -RuleID "2.3.11.12" -Key "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "AuditReceivingNTLMTraffic" -Type DWord -Value 2

# 2.3.11.14 - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers (Audit all = 1)
Set-CISReg -RuleID "2.3.11.14" -Key "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "RestrictSendingNTLMTraffic" -Type DWord -Value 1

# 2.3.17.1 - User Account Control: Admin Approval Mode for Built-in Administrator (Enabled)
Set-CISReg -RuleID "2.3.17.1" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "FilterAdministratorToken" -Type DWord -Value 1

# 2.3.17.2 - User Account Control: Behavior of elevation prompt for administrators (Prompt for consent on secure desktop = 2)
Set-CISReg -RuleID "2.3.17.2" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ConsentPromptBehaviorAdmin" -Type DWord -Value 2

# 2.3.17.3 - User Account Control: Behavior of elevation prompt for standard users (Automatically deny = 0)
Set-CISReg -RuleID "2.3.17.3" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ConsentPromptBehaviorUser" -Type DWord -Value 0