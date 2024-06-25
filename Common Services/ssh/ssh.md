- **tags:** #common-services #ssh
- -------------------
# SSH
## Enumeration
The secure shell protocol is normally assigned to port 22. We can use this protocol to connect to a remote host and do as we please, all data sent will be encrypted so we shouldn't need to worry much for an #MITM attack.
![[nmap-ssh-scan.png]]
## Brute-Force Login
We can use [[hydra]] for brute-forcing valid credentials.
![[hydra-ssh.png]]
### Resource Labs:
- [Set up Docker container with ssh service](https://hub.docker.com/r/linuxserver/openssh-server)