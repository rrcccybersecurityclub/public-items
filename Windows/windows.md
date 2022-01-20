Fix Text: Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Configure Solicited Remote Assistance" to "Disabled".
Fix Text: Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Disallow Autoplay for non-volume devices" to "Enabled".
Fix Text: Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".
Fix Text: Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Turn off AutoPlay" to "Enabled:All Drives".
Fix Text: Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Always install with elevated privileges" to "Disabled".
Fix Text: Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> "Allow Basic authentication" to "Disabled".
Fix Text: Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Allow Basic authentication" to "Disabled".
Fix Text: Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".
Fix Text: Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM"
Fix Text: Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Store password using reversible encryption" to "Disabled".
Fix Text: Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Limit local account use of blank passwords to console logon only" to "Enabled".
Fix Text: Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Remotely accessible registry paths" with the following entries:
System\CurrentControlSet\Control\ProductOptions 
System\CurrentControlSet\Control\Server Applications 
Software\Microsoft\Windows NT\CurrentVersion

Fix Text: Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".
Fix Text: Ensure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Shares that can be accessed anonymously" contains no entries (blank).
Fix Text: Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".
Fix Text: Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Act as part of the operating system" to be defined but containing no entries (blank).
Fix Text: Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Debug programs" to only include the following accounts or groups:

reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer\" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Peernet\" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\" /v "AllowBasic" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" /v "AllowBasic" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer\" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" /v "SMB1" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" /v "Start" /t REG_DWORD /d 4 /f

Auditlist: 

auditpol /set /subcategory:"logon" /Success:Enable /Failure:Enable 

auditpol /set /subcategory:"logon" /Success:Enable /Failure:Enable 

auditpol /set /subcategory:"logoff" /Success:Enable /Failure:Enable 

auditpol /set /subcategory:"computer account management" /Success:Enable /Failure:Enable 

auditpol /set /subcategory:"computer account management" /Success:Enable /Failure:Enable 

auditpol /set /subcategory:"computer account management" /Success:Enable /Failure:Enable 

auditpol /set /subcategory:"security group management" /Success:Enable /Failure:Enable 

 See these audits in Event Viewer 

 

View Logs 

Logons: wevtutil qe Security "/q:*[System [(EventID=4624)]]" /f:text /c:1 

Failed logons: wevtutil qe Security "/q:*[System [(EventID=4625)]]" /f:text /c:1 

Account created: wevtutil qe Security "/q:*[System [(EventID=4720)]]" /f:text /c:1 

Account deleted: wevtutil qe Security "/q:*[System [(EventID=4726)]]" /f:text /c:1 

Account changed: wevtutil qe Security "/q:*[System [(EventID=4738)]]" /f:text /c:1 

Software installed: wevtutil qe Application "/q:*[System [(EventID=11707)]]" /f:text /c:1 

Member added to group: wevtutil qe Security "/q:*[System [(EventID=4732)]]" /f:text /c:1 

Member removed group: wevtutil qe Security "/q:*[System [(EventID=4733)]]" /f:text /c:1 

Service installed: wevtutil qe System "/q:*[System [(EventID=7045)]]" /f:text /c:1 

 