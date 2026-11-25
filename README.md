# CIS-L1-Windows-2025
Also copy or install Administrative Templates (.admx) 
 1) Path for - C:\Windows\PolicyDefinitions
 2) Central Store location - C:\Windows\SYSVOL\Policies\PolicyDefinitions

# Create GPO in DC than run this powershell script as Admin.
  GPO Name : CIS-Benchmark-Win2025-L1-Remediation
             CIS-Win2025-L1-18.9.3.1-to-End
             CIS-Win2025-L1-Remaining-Remediation
             Set-CISServer2025Remediation
