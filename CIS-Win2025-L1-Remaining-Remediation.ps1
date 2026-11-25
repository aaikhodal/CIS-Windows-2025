#Requires -Modules GroupPolicy
#Requires -RunAsAdministrator

$GPOName = "CIS-Win2025-L1-Remaining-Remediation"

if (-not (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue)) {
    New-GPO -Name $GPOName -Comment "CIS Windows Server 2025 L1 Remediation (2026-11-25 Scan Remaining Findings)" | Out-Null
    Write-Host "[+] Created GPO: $GPOName" -ForegroundColor Green
} else {
    Write-Host "[*] Using existing GPO: $GPOName" -ForegroundColor Yellow
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
# SECTION 18: ADMINISTRATIVE TEMPLATES - COMPUTER (REMAINING FAILED)
# ==============================================================================

# 18.6.7.5 & 18.6.7.7 - Lanman Server
Set-CISReg -RuleID "18.6.7.5" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanServer" -ValueName "EnableMailslots" -Type DWord -Value 0
Set-CISReg -RuleID "18.6.7.7" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanServer" -ValueName "AuthRateLimiterDelayInMs" -Type DWord -Value 2000

# 18.6.8.2 & 18.6.8.5 - Lanman Workstation
Set-CISReg -RuleID "18.6.8.2" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "AuditServerDoesNotSupportEncryption" -Type DWord -Value 1
Set-CISReg -RuleID "18.6.8.5" -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName "EnableMailslots" -Type DWord -Value 0

# 18.7.12 & 18.7.13 - Point and Print Restrictions
Set-CISReg -RuleID "18.7.12" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "NoWarningNoElevationOnInstall" -Type DWord -Value 0
Set-CISReg -RuleID "18.7.13" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "UpdatePromptSettings" -Type DWord -Value 0

# 18.9.13.1 - Early Launch Antimalware
Set-CISReg -RuleID "18.9.13.1" -Key "HKLM\System\CurrentControlSet\Policies\EarlyLaunch" -ValueName "DriverLoadPolicy" -Type DWord -Value 3

# 18.9.19.2 - 18.9.19.6 - Group Policy Processing
Set-CISReg -RuleID "18.9.19.2" -Key "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ValueName "NoBackgroundPolicy" -Type DWord -Value 0
Set-CISReg -RuleID "18.9.19.3" -Key "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ValueName "NoGPOListChanges" -Type DWord -Value 0
Set-CISReg -RuleID "18.9.19.4" -Key "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ValueName "NoBackgroundPolicy" -Type DWord -Value 0
Set-CISReg -RuleID "18.9.19.5" -Key "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ValueName "NoGPOListChanges" -Type DWord -Value 0
Set-CISReg -RuleID "18.9.19.6" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableCdp" -Type DWord -Value 0

# 18.9.20.1.1 - Internet Communication Settings
Set-CISReg -RuleID "18.9.20.1.1" -Key "HKLM\Software\Policies\Microsoft\Windows NT\Printers" -ValueName "DisableWebPnPDownload" -Type DWord -Value 1

# 18.9.25.1 - 18.9.25.8 - Windows LAPS
Set-CISReg -RuleID "18.9.25.1" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName "BackupDirectory" -Type DWord -Value 2 # 2 = Active Directory (1 = Entra ID)
Set-CISReg -RuleID "18.9.25.2" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName "PasswordExpirationProtectionEnabled" -Type DWord -Value 1
Set-CISReg -RuleID "18.9.25.3" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName "ADPasswordEncryptionEnabled" -Type DWord -Value 1
Set-CISReg -RuleID "18.9.25.4" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName "PasswordComplexity" -Type DWord -Value 4
Set-CISReg -RuleID "18.9.25.5" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName "PasswordLength" -Type DWord -Value 15
Set-CISReg -RuleID "18.9.25.6" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName "PasswordAgeDays" -Type DWord -Value 30
Set-CISReg -RuleID "18.9.25.7" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName "PostAuthenticationResetDelay" -Type DWord -Value 8
Set-CISReg -RuleID "18.9.25.8" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ValueName "PostAuthenticationActions" -Type DWord -Value 3

# 18.9.26.1 - Local Security Authority
Set-CISReg -RuleID "18.9.26.1" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "AllowCustomSSPsAPs" -Type DWord -Value 0

# 18.9.28.1 - 18.9.28.7 - Logon
Set-CISReg -RuleID "18.9.28.1" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "BlockUserFromShowingAccountDetailsOnSignin" -Type DWord -Value 1
Set-CISReg -RuleID "18.9.28.2" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "DontDisplayNetworkSelectionUI" -Type DWord -Value 1
Set-CISReg -RuleID "18.9.28.3" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "DontEnumerateConnectedUsers" -Type DWord -Value 1
Set-CISReg -RuleID "18.9.28.4" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnumerateLocalUsers" -Type DWord -Value 0
Set-CISReg -RuleID "18.9.28.5" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "DisableLockScreenAppNotifications" -Type DWord -Value 1
Set-CISReg -RuleID "18.9.28.6" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "BlockDomainPicturePassword" -Type DWord -Value 1
Set-CISReg -RuleID "18.9.28.7" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "AllowDomainPINLogon" -Type DWord -Value 0

# 18.9.39.3 - Security Account Manager
Set-CISReg -RuleID "18.9.39.3" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\SAM" -ValueName "SamChangePasswordRpcMethods" -Type DWord -Value 1

# 18.10.4.2, 18.10.6.1, 18.10.8.1, 18.10.9.1.1, 18.10.14.1, 18.10.15.1-2
Set-CISReg -RuleID "18.10.4.2"   -Key "HKLM\Software\Policies\Microsoft\Windows\Appx" -ValueName "BlockNonAdminUserInstall" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.6.1"   -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "MSAOptional" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.8.1"   -Key "HKLM\Software\Policies\Microsoft\Windows\Explorer" -ValueName "NoAutoplayfornonVolume" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.9.1.1" -Key "HKLM\Software\Policies\Microsoft\Biometrics\FacialFeatures" -ValueName "EnhancedAntiSpoofing" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.14.1"  -Key "HKLM\Software\Policies\Microsoft\Windows\Connect" -ValueName "RequirePinForPairing" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.15.1"  -Key "HKLM\Software\Policies\Microsoft\Windows\CredUI" -ValueName "DisablePasswordReveal" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.15.2"  -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -ValueName "EnumerateAdministrators" -Type DWord -Value 0

# 18.10.16.4 - 18.10.16.7 - Data Collection and Preview Builds
Set-CISReg -RuleID "18.10.16.4" -Key "HKLM\Software\Policies\Microsoft\Windows\DataCollection" -ValueName "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.16.5" -Key "HKLM\Software\Policies\Microsoft\Windows\DataCollection" -ValueName "EnableOneSettingsAuditing" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.16.6" -Key "HKLM\Software\Policies\Microsoft\Windows\DataCollection" -ValueName "LimitDiagnosticLogCollection" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.16.7" -Key "HKLM\Software\Policies\Microsoft\Windows\DataCollection" -ValueName "LimitDumpCollection" -Type DWord -Value 1

# 18.10.18.2 - 18.10.18.6 - Desktop App Installer
Set-CISReg -RuleID "18.10.18.2" -Key "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableExperimentalFeatures" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.18.3" -Key "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableHashOverride" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.18.4" -Key "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableLocalArchiveMalwareScanOverride" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.18.5" -Key "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableMSAppInstallerProtocol" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.18.6" -Key "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableMicrosoftStoreSourceCertificateValidationBypass" -Type DWord -Value 0

# 18.10.26.1.1 - 18.10.26.4.2 - Event Log Service
Set-CISReg -RuleID "18.10.26.1.1" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" -ValueName "Retention" -Type String -Value "0"
Set-CISReg -RuleID "18.10.26.1.2" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" -ValueName "MaxSize" -Type DWord -Value 32768
Set-CISReg -RuleID "18.10.26.2.1" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "Retention" -Type String -Value "0"
Set-CISReg -RuleID "18.10.26.2.2" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -Type DWord -Value 196608
Set-CISReg -RuleID "18.10.26.3.1" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup" -ValueName "Retention" -Type String -Value "0"
Set-CISReg -RuleID "18.10.26.3.2" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup" -ValueName "MaxSize" -Type DWord -Value 32768
Set-CISReg -RuleID "18.10.26.4.1" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" -ValueName "Retention" -Type String -Value "0"
Set-CISReg -RuleID "18.10.26.4.2" -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" -ValueName "MaxSize" -Type DWord -Value 32768

# 18.10.29.2 & 18.10.29.5 - File Explorer

Set-CISReg -RuleID "18.10.29.2" -Key "HKLM\Software\Policies\Microsoft\Windows\Explorer" -ValueName "NoZoneInfoOnFileCopy" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.29.5" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "PreXPSP2ShellProtocolBehavior" -Type DWord -Value 0


# 18.10.42.1 - Microsoft Accounts

Set-CISReg -RuleID "18.10.42.1" -Key "HKLM\Software\Policies\Microsoft\MicrosoftAccount" -ValueName "DisableUserAuth" -Type DWord -Value 1


# 18.10.58 - 18.10.92 - RSS, Search, SmartScreen, Ink, Installer, Winlogon, WinRM, Security Center

Set-CISReg -RuleID "18.10.58.1"   -Key "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "DisableEnclosureDownload" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.58.2"   -Key "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "AllowBasicAuthInClear" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.59.3"   -Key "HKLM\Software\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowIndexingEncryptedStoresOrItems" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.76.2.1" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableSmartScreen" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.76.2.1" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "ShellSmartScreenLevel" -Type String -Value "Block"
Set-CISReg -RuleID "18.10.80.2"   -Key "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" -ValueName "AllowWindowsInkWorkspace" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.81.1"   -Key "HKLM\Software\Policies\Microsoft\Windows\Installer" -ValueName "EnableUserControl" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.81.2"   -Key "HKLM\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.82.1"   -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableMPRNotifications" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.89.1.3" -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" -ValueName "AllowDigest" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.89.2.4" -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "DisableRunAs" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.92.2.1" -Key "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -ValueName "DisallowExploitProtectionOverride" -Type DWord -Value 1

# 18.10.93.* - Windows Update

Set-CISReg -RuleID "18.10.93.1.1" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.93.2.1" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.93.2.1" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Type DWord -Value 4
Set-CISReg -RuleID "18.10.93.2.2" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallDay" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.93.4.1" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ManagePreviewBuilds" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.93.4.1" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ManagePreviewBuildsPolicyValue" -Type DWord -Value 0
Set-CISReg -RuleID "18.10.93.4.2" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferFeatureUpdates" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.93.4.2" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 180
Set-CISReg -RuleID "18.10.93.4.3" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferQualityUpdates" -Type DWord -Value 1
Set-CISReg -RuleID "18.10.93.4.3" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 0

# ==============================================================================
# SECTION 18: ADMINISTRATIVE TEMPLATES - USER CONFIGURATION
# ==============================================================================

Set-CISReg -RuleID "19.5.1.1"  -Key "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ValueName "NoToastApplicationNotificationOnLockScreen" -Type DWord -Value 1
Set-CISReg -RuleID "19.7.5.1"  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "SaveZoneInformation" -Type DWord -Value 2
Set-CISReg -RuleID "19.7.5.2"  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "ScanWithAntiVirus" -Type DWord -Value 3
Set-CISReg -RuleID "19.7.8.1"  -Key "HKCU\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "ConfigureWindowsSpotlight" -Type DWord -Value 2
Set-CISReg -RuleID "19.7.8.2"  -Key "HKCU\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableThirdPartySuggestions" -Type DWord -Value 1
Set-CISReg -RuleID "19.7.8.5"  -Key "HKCU\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableSpotlightCollectionOnDesktop" -Type DWord -Value 1
Set-CISReg -RuleID "19.7.26.1" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoInplaceSharing" -Type DWord -Value 1
Set-CISReg -RuleID "19.7.44.1" -Key "HKCU\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWord -Value 0

# ==============================================================================
# SECTION 2.3.11.2: REMAINING REGISTRY-BACKED SECURITY OPTION
# ==============================================================================


# 2.3.11.2 - Network security: Allow LocalSystem NULL session fallback (Disabled)
Set-CISReg -RuleID "2.3.11.2" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "AllowNullSessionFallback" -Type DWord -Value 0


