- **tags:** #privesc #linux #internalservices
- ----------
# Exploiting Vulnerable Services
A service will always run with the same privileges as the user who ordered its execution. Therefore, after gaining a foothold in the target, we should always list the internal sockets being used and the services being ran on the background.
- `netsat -lantp`
- `systemctl list-timers`
We can use tools like [[procmon.sh]] or *pspy* to conduct our research.