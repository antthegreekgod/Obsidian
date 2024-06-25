- **tags:** #privesc #windows #kernel
- ----------------
# Privilege Escalation
We should always aim for kernel exploits to elevate our privileges. A kernel is a computer program that is the core of an OS and has complete control over every resource and hardware on a system. 
Windows NT kernel philosophy consists of two main modes of operation that determine access to system resources and hardware:
- User Mode: Programs and services running with limited access
- Kernel Mode: Unrestricted access to system resources and functionality.
Kernel exploits on Windows will typically target vulnerabilities in the Windows kernel to execute arbitrary code in order to run privileged system commands or to obtain a system shell.
# PrivEsc Metasploit
In the event of gaining a *Meterpreter* on the target system we can start by running the `getsystem` command to attempt to escalate our privileges through various ways. Another thing we should run is the `suggester` *Metasploit* module.
```bash
msfconsole
# start meterpreter
# send session to background
search suggester
```
Another more manual approach would be using the [windows-exploit-suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) tool. To use such tool, you will need to update its MS vulnerability database and then provide a `.txt` file with the output of the `systeminfo` command of the target.
# Bypassing User Account Control (UAC)
In order to successfully bypass **UAC**, we will need to have access to a user account that is a part of the local administrators group on the Windows target system. **UAC** allows a program to be executed with administrative privileges, consequently prompting the user for confirmation. If the *protection level is set below high*, Windows programs can be executed with elevated privileges *without* prompting the user for *confirmation*. Thus allowing an attacker the possibility to start a *reverse shell* on the remote system.
## Enumerate Users
```cmd
net user #returns users
net localgroup administrators
```
In the event we discover that our user is part of the administrators group we are going to try to bypass the *UAC* control with [UACME](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) and start a new *Meterpreter* session with privileges.