-  #top10 #shellshock
- -----------------
# ShellShock
Shellshock (CVE-2014-6721) is the name given to a family of vulnerabilities in the Bash shell (since V1.3) that allow an attacker to execute remote arbitrary code via Bash, consequently allowing the attacker to obtain remote access to the target system via a [[shells|reverse shell]]. The *Shellshock* vulnerability is caused by a vulnerability in Bash, whereby Bash mistakenly executes trailing commands after a series of characters: **() { :; }; echo; payload**

## Fuzzing for existing FIles
- *Common Extensions* `.pl,.sh,.cgi`
## CGI
*CGI (Common Gateway Interface)* scripts are used by Apache to execute arbitrary commands on the Linux system, after which the output is displayed to the client.
In the context of remote exploitation, *Apache* web servers configured to run *CGI* scripts or *.sh* scripts are also vulnerable to this attack.
### Detection
```bash
nmap -sV <ip> --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi"
```
### PoC
![[shellshock.png]]
### Resource Labs
- [VulnHub SickOs 1.1](https://www.vulnhub.com/entry/sickos-11,132/)
