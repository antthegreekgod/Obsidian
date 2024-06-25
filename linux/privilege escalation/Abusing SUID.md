- **tags:** #privesc #SUID #linux 
- ---------------
# SUID Permissions
If a binary file has the *SUID* permission set and is *owned* by the *root* user, any user running it will temporarily acquire the same privileges as the root user, allowing him to perform actions that he would not normally be able to do as a normal user.
`find / -perm -4000 -ls 2>/dev/null`
### Resource Labs
- [Exim SUID PrivEsc]([https://www.vulnhub.com/entry/pluck-1,178/](https://www.vulnhub.com/entry/pluck-1,178/))