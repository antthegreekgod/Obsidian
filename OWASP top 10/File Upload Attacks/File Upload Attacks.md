- **tags:** #fileUpload #top10 
- ------------
# File Upload Attacks
If the user input and uploaded files are not correctly filtered and validated, attackers may be able to exploit the file upload feature to perform malicious activities, like executing arbitrary commands on the back-end server to take control over it.
# Absent Validation
The most basic type of file upload vulnerability occurs when the web application does not have any form of validation filters on the uploaded files, allowing the upload of any file type by default.
# Bypassing Filters
## Client-Side Validation
Some web applications only rely on front-end *JavaScript* code to *validate* the selected file format before it is uploaded and would not upload it if the file is not in the required format (e.g., not an image). However, as the file format validation is happening on the client-side, we can easily bypass it by directly interacting with the server, skipping the front-end validations altogether with [[Burp Suite]]. Client-side validations are easy to spot as they will not send any request to the server. So if we don't see any request being made while proxying our traffic that means that the validation is being done on the *front-end* by our own browser.
## Blacklist Filters
There may be times, where developers opt to validate the user-input in the back-end against a blacklist of disallowed extensions to prevent uploading web scripts. If the list is not comprehensive enough we will see that there are ways to bypass it. We can craft a wordlist with plenty of alternative (executable) file extensions and start fuzzing with the [[Burp Suite|Intruder]] to see if there's any extension that has been disregarded. For example, for a website that we know that uses *php* as its programming language we could use the following wordlist:
- **PHP**: `.php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module`
## Bypassing Whitelist Filter with Double Extensions
The other type of file extension validation is by utilizing a whitelist of allowed file extensions. A whitelist is generally more secure than a blacklist. The web server would only allow the specified extensions, and the list would not need to be comprehensive in covering uncommon extensions. 
An example of a vulnerable validation would be:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```
The script uses a Regular Expression (*regex*) to test whether the filename contains any whitelisted image extensions. The issue here lies within the *regex*, as it *only checks* whether the *file name contains* the *extension* and *not* if it actually *ends* with it. Thus, an example of a filename that could execute `PHP` code bypassing the previous validation could be any file ending with: `.png.php`
**Fixed with Strict Regex:**
```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```
## Reverse Double Extensions
Even if the file upload functionality uses a strict regex pattern that only matches the final extension in the file name, the organization may use the insecure configurations for the web server. For example, the `/etc/apache2/mods-enabled/php7.4.conf` for the `Apache2` web server may include the following configuration:
```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```
The file name `shell.php.jpg` should pass the earlier whitelist test as it ends with (`.jpg`), and it would be able to execute PHP code due to the above misconfiguration, as it contains `.php` in its name.
## Character Injection
Like we did with [[Local File Inclusion#Null Byte|Local File Inclusion]] url's, we can try to bypass the filters with `PHP` *null byte* injections (`shell.php%00.png`). Note that this method will only work for servers with a `PHP` version prior to **5.X** as it causes the server to end the file name after the *%00* , and store it as `shell.php`, while still passing the whitelist.
Here's a list of other character we may try injecting:
- `%20`
- `%0a`
- `%00` *php null byte*
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:` *for servers hosted on Windows*
## .htaccess
[".htaccess files provide a way to make configuration changes on a per-directory basis."](https://thibaud-robin.fr/articles/bypass-filter-upload/), so if we are against an *Apache* server with upload functionality and we are able to ubload a file named `.htaccess`  we may want to include the following to override the `.php` blacklisting filter.
```.htaccess
AddType application/x-httpd-php .php16
```
Thus, we've now created an alternative `PHP` extension (`.php16`).
## Bypassing Type Filters
### Content-Type
*Our browsers automatically set the Content-Type header when selecting a file* through the file selector dialog, usually derived from the file extension. However, since our browsers set this, this operation is a client-side operation, and *we can manipulate* it to change the perceived file type and potentially bypass the type filter. We may start by *fuzzing* the *Content-Type* header with *SecLists*' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) through [[Burp Suite|Burp Intruder]], to see which types are allowed.
### Magic Numbers
The second and more common type of file content validation is testing the uploaded file's *MIME-Type*. *Multipurpose Internet Mail Extensions (MIME)* is an internet standard that determines the type of a file through its general format and bytes structure. This is usually done by inspecting the first few bytes of the file's content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime).
![[magic numbers.png]]
We can then bypass the *MIME-Type* filters by modifying the first 4 bytes of the file while still leaving our payload.
# Limited File Uploads
Certain file types, like `SVG`, `HTML`, `XML`, and even some image and document files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files. This is why fuzzing allowed file extensions is an important exercise for any file upload attack. It enables us to explore what attacks may be achievable on the web server.
## XSS
The most basic example is when a web application allows us to upload `HTML` files. Although HTML files won't allow us to execute code (e.g., PHP), it would still be possible to implement JavaScript code within them to carry an XSS or CSRF attack on whoever visits the uploaded HTML page.
Another example of *XSS* attacks is web applications that display the *metadata* of our uploaded file. We can modify our *metadata* with **exiftool**  so when image's metadata is displayed, the XSS payload should be triggered, and the JavaScript code will be executed to carry the XSS attack. Furthermore, if we change the image's MIME-Type to `text/html`, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.
```bash
exiftool -Comment=' "><img src=1 onerror=alert(document.cookie)>' image.jpg
```
Finally, one could attempt a *XSS* attack via an *SVG* image:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
## [[XXE]]
With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server. The following example can be used for an *SVG* image that leaks the content of (`/etc/passwd`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [< passwd SYSTEM file:///etc/passwd >]>
	<svg>
		&passwd;
	</svg>
```
**NOTE:** One could use an *XXE* attack to review the `PHP` code with the usage of [[wrappers]].
### Resource Labs:
- *HTB* final assessment.
- [File Upload Laboratory](https://github.com/moeinfatehi/file_upload_vulnerability_scenarios)