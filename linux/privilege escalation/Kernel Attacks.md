- **tags:** #privesc #kernel #linux 
- -------------
# Kernel Attaks
The kernel is the central part of the operating system, which is responsible for managing system resources such as memory, processes, files and devices. Due to its critical role in the system, any vulnerability in the kernel can have serious consequences on the system security. In older versions of the Linux kernel, vulnerabilities have been discovered that can be exploited to allow attackers to gain root access to the system.
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) is a great tool for detecting possible kernel exploits.
A more *manual approach*  way to identify exploits is to issue the command `uname -a` (and `cat /etc/lsb-release`) and search Google for the kernel version.
## Example
The *Vulnhub Machine* from the External Resources section is vulnerable to a [[ShellShock]] attack. Once inside the system one can elevate its privileges via the *Dirty Cow* that takes advantage of a [[Race Condition]] vulnerability on the *kernel*.
### External Resources
- [Vulnhub Machine](https://www.vulnhub.com/entry/sumo-1,480/)
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) *mainly focused on kernel exploits*
- [HTB Linux Local Privilege Escalation module](https://academy.hackthebox.com/module/51/section/467)