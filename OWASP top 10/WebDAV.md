- **tags:** #webDAV
- -------------------
# WebDAV
*WebDAV* (Web Distributed Authoring & Versioning) is an HTTP extension that allows clients to update, delete, move and copy files on a web server. *WebDAV* is used to enable a web server to act as a file server.
If during our enumeration phase we see that the website is implementing the *WebDav* extensions and we have valid credentials we may take advantage to upload a reverse shell. There's a tool called *davtest* that will fuzz for the allowed methods and types of files permitted.  
```bash
davtest -url http://<ip>/webdav/ -auth username:password
```
In case we didn't have any credentials we can use [[hydra]] to try to brute-force our way in:
```bash
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.2.17.124 http-get /webdav/
```
Once we have tested the site with *davtest* we can take advantage of *cadaver* for an easy interaction with the **WebDAV** utilities.
```bash
cadaver <url>
```
### Resource Labs
- [docker pull bytemark/webdav](https://hub.docker.com/r/bytemark/webdav)