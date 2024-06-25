- **tags:** #cron #linux #privesc 
- -----------
# Cron
Detection and exploitation of cron jobs is a technique used by attackers to elevate their level of access on a compromised system. For example, if an attacker detects that a file is being executed by the user "*root*" through a *cron* job that runs at regular time intervals, and realizes that the permissions defined in the file are misconfigured, he could manipulate the contents of the file to include malicious instructions which would be executed in a privileged way as the user 'root', since it corresponds to the user who is executing that file.
## Cron jobs detection
- [[procmon.sh]]
- [pspy](https://github.com/DominicBreuker/pspy)