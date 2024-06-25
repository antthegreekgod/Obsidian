- **tags:** #privesc #enumeration #windows 
- -------------------
# Manual Enumeration
- *Network Information*
```shell
ipconfig /all
arp -a
route print
```
- *Protection Enumeration*
```powershell
# List the Windows Defender Protections
Get-MpComputerStatus
# List Apps blocked by the AppLocker Policy (can be set on the Local Security Policy or as a GPO in AD)
Get-AppLockerPolicy -Effective | select-object -ExpandProperty RuleCollections
get-AppLockerPolicy -Local | test-applockerpolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```
![[Pasted image 20240428112734.png]]
- *System Information*
```powershell
systeminfo
set # pay attention to PATH, HOME DRIVE, HOME PATH
netstat -ano # grab PID
tasklist /svc | findstr PID # spot non-standard processes
wmic qfe # display hotfixes
Get-HotFix | ft -AutoSize # display hotfixes
wmic product get name # list installed software
Get-WmiObject -Class Win32_Product |  select Name, Version # list installed software
```
- *User & Group Information*
```powershell
echo %USERNAME%
whoami /priv
whoami /groups
net user
net localgroup
net localgroup administrators
query user
query session
net accounts # list password policy
```
- *some quick kernel exploit checks on Windows 10* (Print/HiveNightamre)
```powershell
ls \\.\pipe\spoolss
icacls C:\Windows\System32\config\SAM # Check if users have Read and Execute access
```