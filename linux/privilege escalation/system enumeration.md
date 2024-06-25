- **tags:** #enumeration #privesc #linux 
--------------------------------
# Manual Enumeration
```bash
whoami
id
cat /etc/passwd
cat /etc/security/opasswd
cat /etc/group
getent group sudo
hostname
ipconfig
sudo -l
sudo -V
cat /etc/os-release
echo $PATH
env
cat /etc/shells
cat /proc/version
ls_cpu
lsblk # lists block devices
lpstat # lists printers
cat /etc/fstab # maybe find creds for mounted devices
route || netstat -rn
arp -a
cat /etc/resolv.conf # watch out for internal DNS
cat /etc/hosts
find / -perm -4000 -ls 2>/dev/null
find / -perm -1000 -ls 2>/dev/null
getcap -r / 2>/dev/null
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
ls /var/spool/cron/crontab/
ps -faux | grep root
bash --version # 4.1 or lower vulnerable to shellshock
ls -la /var/temp /temp /dev/shm
systemctl list-timers #look for made up names
lastlog
who || w || finger # see if anyone esle is currently on the system
find / -name \*_hist -o -name \*_history -ls 2>/dev/null # locate history files
apt list --installed | awk '{print $1}' FS=\/ # list installed packages
```
Check out [[procmon.sh]] for a manual approach on how to list current processes.
# Automated Tools
- [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration)
- [LinEnum.sh](https://github.com/rebootuser/LinEnum)
# PrivEsc
- [GTFOBins](https://gtfobins.github.io)
- [hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [LinPEAS](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) *mainly focused on kernel exploits*
# CronJobs
Linux implements task scheduling through a utility called *Cron*. *Cron* can be used to automate or repeat a wide variety of functions on a system, from daily backups to system upgrades and patches. The *crontab* file is a configuration file that is used by the *Cron* utility to store and track *Cron* jobs that have been created. In order to elavte our privileges, we will need to find and identify cron jobs scheduled by the root user or the files being processed by the cron job.
 We can list the cron jobs scheduled by the current user with:
 ```bash
 crontab -l
```
Finding the *cron* jobs scheduled by other users is going to require of configuration files enumeration.