- **tags:** #common-services #NFS
- -------------
# Introduction
`Network File System` (`NFS`) purpose is to access file systems over a network as if they were local. It can only be used between Linux and Unix systems. The most common authentication is via UNIX `UID`/`GID` and `group memberships`. **One problem is that the client and server do not necessarily have to have the same mappings of UID/GID to users and groups**, and the server does not need to do anything further. No further checks can be made on the part of the server. This is why NFS should only be used with this authentication method in trusted networks.
# Enumeration
[[Nmap]] has some NSE scripts that can be used for the scans. *NFSv4* uses only TCP port *2049*, however older versions may need more open ports to run the service. 
```bash
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```
We can use other tools to show show mount information for an NFS server.
```bash
# Show Available NFS Shares
showmount -e 10.110.89.12
```
# Mounting NFS Share
```bash
mkdir /mnt/target-NFS
mount -t nfs 10.110.89.12:/ /mnt/target-NFS/ 
```
# Dangerous Settings
Once we have mounted an NFS share will have the opportunity to access the rights and the usernames and groups to whom the shown and viewable files belong (`ls -lan`). **Because once we have the usernames, group names, UIDs, and GUIDs, we can create them on our system and adapt them to the NFS share to view and modify the files.**
We can also use NFS for further escalation. For example, if we have access to the system via SSH and want to read files from another folder that a specific user can read, we would need to upload a shell to the NFS share that has the `SUID` of that user and then run the shell via the SSH user.