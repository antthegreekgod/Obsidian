- **tags:** #linux #privesc #0days
- ------------
# Dirty Pipe
All kernels from version `5.8` to `5.17` are affected and vulnerable to this vulnerability.
```bash
searchsploit dirty pipe
```
# pkexec
Hidden for more than 10 years, discovered in November 2021 and fixed two months later.
- [pkexec exploit](https://github.com/arthepsy/CVE-2021-4034)
# sudo
One of the latest vulnerabilities for `sudo` carries the CVE-2021-3156 and is based on a heap-based buffer overflow vulnerability.
Affected sudo versions:
- 1.8.31 - Ubuntu 20.04
- 1.8.27 - Debian 10
- 1.9.2 - Fedora 33
- and others
[sudo exploit](https://github.com/blasty/CVE-2021-3156.git)
Another vulnerability was found in 2019 that affected all versions below **1.8.28** ([CVE-2019-14287](https://www.sudo.ws/security/advisories/minus_1_uid/))
