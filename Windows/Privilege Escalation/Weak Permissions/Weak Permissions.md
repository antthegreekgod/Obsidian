- **tags:** #windows #privesc 
- -----------
# Pemissive File System ACLs
- [SharpUp](https://github.com/GhostPack/SharpUp/) tool for detecting service binaries suffering from weak ACLs.
![[modifiable service binaries.png]]
![[icacls sharpup.png]]
SharpUp detects that the "*SecurityService*"  binary is modifiable. We use *icacls.exe* to double check it.
![[exploit SecurityService.png]]
We generate a payload with *msfvenom* and overwrite vulnerable binary.
# Weak Service Permissions
The first image also shows how *SharpUp* detected *WindscribeService*  is modifiable. An attacker could modify the *binPath* and restart the service to execute its payload.
![[modifiable service.png]]
# Unquoted Service Path
When a service is installed, the registry configuration specifies a path to the binary that should be executed on service start. If this binary is not encapsulated within quotes, Windows will attempt to locate the binary in different folders. 
For example if we were dealing with the following binary: 
`C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe`
If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service:
- `C:\Program.exe`
- `C:\Program Files (x86)\System.exe`
However, *creating files in the root of the drive or the program files folder requires administrative privileges*. Even if the system had been misconfigured to allow this, *the user probably wouldn't be able to restart the service and would be reliant on a system restart to escalate privileges*. Although it's not uncommon to find applications with unquoted service paths, it isn't often exploitable.
