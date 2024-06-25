- **tags:** #LFI #top10 
----------------------
# LFI
## Basic Explotation
Let's say we are hosting a server with `PHP` as the programming language on the back-end:
```php
<?php
	//index.php
	$file=$_GET['file'];
	include($file);
?>
```
The way it's been set, this server will display any system document requested after the `file` parameter on a *GET* request. We are not doing any kind of input validation nor sanitation, therefore an attacker could retrieve any kind of sensitive files (*Local File Inclusion*).
![[LFI1.png]]
## Path Transversal
A developer may want to modify the previous code by attempting to restrict the location of the system files which a client should have access.
```php
<?php
	//index.php
	$file=$_GET['file'];
	include('/var/www/html'.$file);
?>
```
Once again, an attacker could easily bypass the restriction using system *relative paths*.
![[LFI2.png]]
Now, the developer might want to user sanitization techniques like [[Sanitation and Validation Techniques#str_replace();|str_replace();]]  to strengthen the security measures:
```php
<?php
	//index.php
	$file=$_GET['file'];
	$file=str_replace("../","",$file);
	include('/var/www/html' . $file);
?>
```
![[LFI3.png]]
An attacker could still bypass it with `....//....//.....//` since the sanitation is not being applied recurrently. At this point the developer might opt to use input validation with functions such as [[Sanitation and Validation Techniques#preg_match();|preg_match()]] to ensure that the user input doesn't contain the name of any sensitive directory:
```php
<?php
	//index.php
	$file=$_GET['file'];
	$file=str_replace("../","",$file);

	if(preg_match("/\/etc/passwd", $file) === 1){
		echo "\n[+] Can't display the requested file\n";
	}else{
		include('/var/www/html' . $file);
	}
?>
```
There are still ways to get around it:
![[LFI4.png]]
## Bypassing PHP Extensions
### Null Byte
**PHP versions before 5.5** were vulnerable to `null byte injection`, which means that adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it. This is due to how strings are stored in low-level memory, where strings in memory must use a null byte to indicate the end of the string.
- Use *docker* container for practice:  `docker pull tommylau/php-5.2` (`docker run -dit --name php5.2 <containerName>`)
![[nullbyte.png]]
**Note**: urlencode(`%00`) --> `\0`
## Reading PHP code
We can use `PHP` [[wrappers]] to retrieve the source code from `PHP` files:
- With *php://filter/convert.base64-encode/resource=*`secret.php` 
![[wrappers.png]]
**Note:** Remember that this technique will only work if the web server is using `PHP` on the back-end. You can also use thid wrapper to retrieve files other than `.php`  like */etc/passwd*.

- With *php://filter/read=string.rot13/resource=*`secret.php`
![[wrappers2.png]]
- With *php://filter/convert.iconv.utf-8.utf-16/resource=*`secret.php`
![[wrappers3.png]]
**Note:** You will need to use the `view-source:` tab to view the code.
## RCE with PHP Wrappers
We can also use `PHP` [[wrappers]] to execute system commands:
- *php://input*
![[wrappers4.png]]
**Note:** To use this wrapper our request must be using the *POST* method and the `/etc/php/X.X/apache2/php.ini` must have the `allow_url_include` set to **ON**.

- *data: //text/plain;base64,*
![[wrappers5.png]]
**Note:** To use this wrapper the `/etc/php/X.X/apache2/php.ini` configuration file must have the `allow_url_include` set to **ON**.

For both [[wrappers]] the best payload would be the `<?php system($_GET["cmd"]);?>` to get a [[shells|webshell]], and just add the command to execute after the `cmd` parameter.
There's one last [[wrappers|wrapper]] that would allow us to execute commands on the system. It's called *expect://* and it is an external [[wrappers|wrapper]] so it would have to be manually installed on the system. Once again, to be able to use it, the `allow_url_include` setting must be **ON**. 
## Filter Chains
This is insane, having full control of the *php://filter/* wrapper we are going to be able to inject code with **NO** need of having the `allow_url_include` setting to be ON!!!
### PoC
When playing with *convert.iconv* combined with *base64* conversion and reversion, we are able to inject characters at the beggining of our string. The character injected will depend on the type of *encoding* used.
![[wrappers7.png]]
The [Filter Chain generator Tool](https://github.com/synacktiv/php_filter_chain_generator) can automate this process for us.
![[wrappers6.png]]
Therefore we can now use this tool to generate our webshell and later upgrade to a reverse shell.
![[wrappers8.png]]
![[wrappers9.png]]
### Resource Labs
- Just start a docker container and set up your own `Apache` server with `PHP` (`docker pull debian:latest`).
## Remote File Inclusion
In some cases, we may also be able to include remote files "Remote File Inclusion (RFI)", if the vulnerable function allows the inclusion of remote URLs. This allows two main benefits:
- Enumerating local-only open ports
- Gaining RCE by including a malicious script that we host
## Log Poisoning
Given the case we discover a vector for a *LFI* with access to the logs, we can gain *RCE* through what it's known as *Log Posioning*. We send our payload in the *User-Agent* header and once we load the log file, the code will be interpreted giving us RCE.
### Examples:
- `apache2` log path (`/var/log/apache2/access.log`):
![[apacheLogPoisoning 1.png]]
- `ssh` log path (`/var/log/btmp`)
![[sshLogPoisoning.png]]
### Resource Labs
- *Final Lab from HTB LFI Module*
- [Practice Filter Chains]([https://www.vulnhub.com/entry/pluck-1,178/](https://www.vulnhub.com/entry/pluck-1,178/))
- [Vulnhub Presidential](https://www.vulnhub.com/entry/presidential-1,500/)