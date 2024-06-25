- **tags:** #common-services #ftp
-----------------
FTP stands for file transfer protocol, and as the name may suggest, it is a protocol normally used on port 21 for file sharing.
# ftp
## Enumeration
After an initial scan with [[nmap]] we see that the port 21 is open and identified as [[FTP]].
![[ftp-ports.png]]

Sometimes we can login in to the system using the anonymous user and a NULL password.
```bash
nmap --script ftp-anon <ip> -p21 # will report if its vulnerable to anonymous login
```
![[ftp-anon.png]]
## Brute-Force for Credentials
We can use [[hydra]] for brute-forcing valid credentials.
```bash
hydra -l ant -P /usr/share/wordlists/rockyou.txt -f -t 64 ftp://127.0.0.1
```
![[hydra-ftp.png]]
Note that we have used the `-f` switch so hydra stops after the first valid match.
## ftp bounce attack
There may be times where can take advantage from an external FTP server to enumerate/interact with internal services.  The attacker uses a `PORT` command to trick the FTP connection into running commands and getting information from a device other than the intended server.
```bash
# tests whether the fpt server is prone to bounce attack or not
nmap -Pn -v -n -p80 -b anonymous:password@<ftp_server_ip> <internal_ip>
```
# Download all available files at once
We can download all the files and folders we have access to at once using `wget`:
```bash
wget -m --no-passive ftp://anonymous:''@10.129.14.136
```
# FTP running TLS/SSL Encryption
We can use the client `openssl` and communicate with the FTP server.
```bash
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```
### Resource Labs:
- [For Brute-Force attacks](https://github.com/garethflowers/docker-ftp-server)
- [ftp-anon](https://github.com/metabrainz/docker-anon-ftp)
