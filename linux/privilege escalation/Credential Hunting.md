- **tags**: #linux #privesc #credentials 
- ------------
# Files
Files to review:
- Configuration files
- Scripts
- Databases
- Cronjobs
- Notes
- SSH Keys
## Configuration Files
- List all configuration files from root directory:
```bash
for extension in {.config,.conf,.cnf}; do echo -e "\nFile extension ${extension}:\n"; find / -name *$extension 2>/dev/null | grep -v "usr\|core\|fonts"; done
```
- Run a keyword scan on the config files found:
```bash
for file in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib"); do echo -e "\nFile $file:\n"; grep "user\|password\|pass" $file 2>/dev/null | grep -v "\#"; done 
```
## Databases
- List all db files recursively from the root directory:
```bash
for extension in {.db,.sql,.db*,db}; do echo -e "\nFile extension ${extension}:\n"; find / -name *$extension 2>/dev/null; grep -v "doc\|lib\|headers\|share\|man"; done
```
## Notes
- List all *.txt* and *no extension* files recursively from the home directory:
```bash
# find files with the .txt extension or with no dot within the name
find /home/* -type f -name "*.txt" -o ! -name "*.*" -type f
```
## Scripts
- List all scripts:
```bash
for extension in {.py,.pyc,.pl,.go,.jar,.c,.sh};do echo -e "\nFile extension $extension:\n"; find / -name *$extension 2>/dev/null | grep -v "doc\|lib\|headers\|share"; done
```
## Cronjobs
```bash
cat /etc/crontab
ls -la /etc/cron.*/
```
## SSH Keys
Since the SSH keys can be named arbitrarily, we cannot search them for specific names. However, their format allows us to identify them uniquely because, whether public key or private key, both have unique first lines to distinguish them.
- SSH Private keys
```bash
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null 
```
- SSH Public Keys
```bash
grep -rnw "ssh-rsa" /home/* 2>/dev/null
```
## Bash History and Profiles
- View contents of *.bashrc, .bash_history, .bash_profile*:
```bash
tail -n5 /home/*/.bash*
```
## Memory Stored Creds
Many applications and processes work with credentials needed for authentication and store them either in memory or in files so that they can be reused.
- [mimipenguin.py](https://github.com/huntergregal/mimipenguin/tree/master)
## All in One
- [LaZagne](https://github.com/AlessandroZ/LaZagne)
## Browser Passwords
- [Firefox Decrypt](https://github.com/unode/firefox_decrypt)