#=================================================
# Initial survey 
#=================================================
echo "======================"
echo "| initial survey     |"
echo "======================"
Get-Date
echo "setting execution policy:"
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine
echo "confirming execution policy:"
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
echo "computer name:" $env:computername
(Get-WMIObject win32_operatingsystem) | Select Version
echo "PID:" $PID
Write-Output "currently have administrative rights:"; ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
echo "groups for current user:"
[security.principal.windowsidentity]::getcurrent() | select -ExpandProperty groups | ForEach-Object {Get-Localgroup -sid $_.value -ErrorAction SilentlyContinue}
get-computerinfo
echo "======================"
echo "| networking survey  |"
echo "======================"
getmac
get-netadapater |format-list -property name, promiscuousmode
Get-NetIPConfiguration
Get-NetIPAddress|format-table
echo "netstat:"
netstat -anob
echo "arp:"
arp -a
net view
net share
echo "======================"
echo "| hardware survey    |"
echo "======================"
get-computerinfo
Get-CimInstance Win32_DiskPartition | Select-Object Index,Name,Blocksize,Bootable,PrimaryPartition,Size | format-table
Get-WmiObject -Class Win32_Processor | Select-Object name, Loadpercentage
echo "======================"
echo "| security checks    |"
echo "======================"
echo "processes:"
Get-Process
echo "loaded DLLs:"
tasklist /m
#suss process: Get-Process -Id <process_id> | select name, path, starttime
# Get-Process -Id <process_id>.Modules <--dlls loaded in
# Get-WmiObject win32_process | select name, ProcessID, ParentProcessId, commandline
# win32_process | Where-Object ($_.Name -eq '<process_name>'}).GetOwner()
echo "services:"
#Get-Service | where-object {$_.Status -eq 'running'}
net start
echo "scheduled tasks:"
schtasks /query
echo "installed drivers:"
Get-WindowsDriver -online | select-object Driver,OriginalFileName,DriverSignature,ProviderName,Date,Logpath
# add /v /FO list for more info ^
echo "audit status:"
Get-LogProperties Security | Format-List enabled
echo "auditpol:"
auditpol /get /category:*
echo "last 20 security events:"
Get-EventLog -Logname Security -Newest 20
#to drill use Get-EventLog security -Index <Index#> <Index#2> <etc> | Format-List *
echo "registered antivirus:"
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Format-List DisplayName,PathToSignedProductExe,PathToSignedReportingExe
echo "defender malware detections:"
Get-MpThreatDetection
echo "checking local administrators; if more than two, this is bad:"
net localgroup administrators
echo "checking for autologon administrators (this is bad too):"
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon
echo "checking anonymous access is restricted (value should be 2 or 1):"
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\control\LSA -name RestrictAnonymous
echo "checking that guest account is disabled:"
Get-WmiObject win32_UserAccount -Filter "Name = 'Guest'" | Select-Object __Server,Disabled
echo "======================"
echo "| persistence checks |"
echo "======================"
echo "registry section:"
Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
echo "winlogon:"
Get-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
echo "enumerating users:"
$names = gci C:\Users | where-object { $_.Name -ne 'Public' -and $_.Name -ne 'default' } | select { $_.Name }
$names
echo "enumerating user startup folders:"
Foreach ($name in $names) {Get-ChildItem ('c:\Users\' + ($name.' $_.Name ') + '\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')}
echo "WMI permanent event registration:"
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
# if any discovered, use page 281 of windows guide to drill further
echo "======================"
echo "| forensic reg keys  |"
echo "======================"
echo "AppInit_Dlls:"
Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\currentversion\windows' -Name AppInit_Dlls
echo "most recently edited registry keys:"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit
echo "most recently opened files:"
reg query HKCU\software\microsoft\windows\currentversion\explorer\recentdocs
echo "final log check; past 60 minutes of logs:"
Get-ChildItem -Path C:\ -recurse | Where-Object {$_.LastWriteTime -ge (Get-Date).AddMinutes(-60)}
echo "ending script"
Get-Date
