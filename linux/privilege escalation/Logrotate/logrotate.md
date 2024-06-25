- **tags:** #privesc #linux 
- ------------
# Introduction
Every Linux system produces large amounts of log files. To prevent the hard disk from overflowing, a tool called `logrotate` takes care of archiving or disposing of old logs. If no attention is paid to log files, they become larger and larger and eventually occupy all available disk space. Furthermore, searching through many large log files is time-consuming. To prevent this and save disk space, `logrotate` has been developed.
`Logrotate` has many features for managing these log files. These include the specification of:
- the **size** of the log file,
- its **age**,
- and the `action` to be taken when one of these factors is reached.
The function of the rotation itself consists in renaming the log files. For example, new log files can be created for each new day, and the older ones will be renamed automatically. Another example of this would be to empty the oldest log file and thus reduce memory consumption.
To exploit `logrotate`, we need some requirements that we have to fulfill.
- **write permissions** on the log files
- logrotate must run as a privileged user or `root`
- vulnerable versions: (3.8.6, 3.11.0, 3.15.0, 3.18.0)
The exploit itself consists in [[Race Condition]] on the renaming of files.
![[Pasted image 20240427115525.png]]
## Example
We have writing access to `access.log` and `access.log.1`, and find out that `logrotate` gets triggered once `access.log` reaches a certain file size, emptying the contents of `access.log` and dumping them on `access.log.2`. We can use a tool named [logrotten](https://github.com/whotwagner/logrotten), to exploit this condition. Our payload will create a symlink so when user root logs in the payload will be triggered under his name.
