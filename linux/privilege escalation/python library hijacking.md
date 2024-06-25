- **tags:** #python #privesc 
- --------------
# Intro
```python
import sys
print(sys.path)
>> ['', '/usr/lib/python38.zip', '/usr/lib/python3.8', '/usr/lib/python3.8/lib-dynload', '/home/hector/.local/lib/python3.8/site-packages', '/usr/local/lib/python3.8/dist-packages', '/usr/lib/python3/dist-packages']
```

When *importing libraries, python will proceed to look for in the above directories*. Let’s say we’ve got access to run a script as *root* and this scripts begins by importing some modules from the system. We may be able to exploit it by creating a file named the same way as the original library and use a payload like the following.
```python
import os
os.system("bash -p")
```

**Miscellaneous:** To list all the python built-in modules run the following.
```python
import sys
print(sys.builtin_module_names)
```
To find out where does a library reside in the system run:
```python
import pwn

print(pwn.__file__) #view where the imported library is located in the system
```
Alternatively: `pip3 show pwn`