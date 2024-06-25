- **tags:** #linux #privesc #pathHijacking
- -----------
# Path Hijacking
*PATH Hijacking* is a technique used by attackers to hijack commands from a Unix/Linux system by *manipulating* the *PATH*. The PATH is an environment variable that defines the search paths for executable files on the system. In some compiled binaries, some of the internally defined commands may be indicated with a *relative path instead of an absolute path*. This means that the binary searches for executable files in the paths specified in the PATH, instead of using the absolute path of the executable file. If an attacker is able to *alter the PATH and create a new file with the same name as one of the internally defined commands in the binary*, he can get the binary to execute the malicious version of the command instead of the legitimate version.
## Example
Let's say we find a binary owned by *root* with *SUID* permissions.
Actual binary (before compilation):
```C
#include <stdio.h>
int main(){
	setuid(0);
	printf("\n[+] You are currently the following user:\n\n");
	system("/usr/bin/whoami");
	printf("\n[+] You are currently the following user:\n\n");
	system("whoami");
}

```
Using the *strings* command we find out that the binary is calling the *whoami* command via its relative path:
![[test.png]]
Altering the *PATH* and creating a new executable named *whoami* and placing it in a directory with a higher priority than */usr/bin* we can elevate our privileges.
