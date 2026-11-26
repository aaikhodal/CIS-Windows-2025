# 17.7.4 Audit MPSSVC Rule-Level Policy Change (Success and Failure)
auditpol /set /subcategory:"{0CCE9232-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# 17.7.5 Audit Other Policy Change Events (Failure)
auditpol /set /subcategory:"{0CCE9234-69AE-11D9-BED3-505054503030}" /success:disable /failure:enable
# 17.8.1 Audit Sensitive Privilege Use (Success and Failure)
auditpol /set /subcategory:"{0CCE9228-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# 17.9.1 Audit IPsec Driver (Success and Failure)
auditpol /set /subcategory:"{0CCE9213-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# 17.9.4 Audit Security System Extension (Success)
auditpol /set /subcategory:"{0CCE9211-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable

Write-Host "4. Configuring Windows Defender Firewall Profiles (Section 9)..." -ForegroundColor Cyan
$Profiles = @(
@{Name="Domain";  Log="%SystemRoot%\System32\logfiles\firewall\domainfw.log"},
@{Name="Private"; Log="%SystemRoot%\System32\logfiles\firewall\privatefw.log"},
@{Name="Public";  Log="%SystemRoot%\System32\logfiles\firewall\publicfw.log"}
)
foreach ($P in $Profiles) {
$FWParams = @{
Name                  = $P.Name
Enabled               = "True"
DefaultInboundAction  = "Block"
NotifyOnListen        = "False"
LogFileName           = $P.Log
LogMaxSizeKilobytes   = 16384
LogBlocked            = "True"
LogAllowed            = "True"
}
Set-NetFirewallProfile @FWParams
}