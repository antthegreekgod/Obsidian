- **tags:** #top10 #SSRF
-------------------
# Intro
Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location. In a typical *SSRF* attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems. This could leak sensitive data, such as authorization credentials.
## Useful Protocols
### file:// 
Using the `file://` protocol might turn useful for reading internal files.
### gopher://
Using this protocol you can specify the IP, port and bytes you want the server to send. Then, you can basically exploit a SSRF to communicate with any TCP server (but you need to know how to talk to the service first). Fortunately, you can use [Gopherus](https://github.com/tarunkant/Gopherus) to create payloads for several services.
# SSRF Example
Let's say we've got access to a website hosting 2 sites. 
- http://172.17.0.2/utility.php (docker container)
```php
<?php
	if(isset($_GET['url'])){
		$url=$_GET['url'];
		echo "\n[+] Listing content from " . $url . ":\n\n";
		include($url);
		// remember that php.ini must have the allow_url_include ON
	}else{
		echo "\n[!] Error: 'url' parameter was not provided\n\n";
	}
?>
```
- http://172.17.0.2/login.php (Production Site)
```html
<!DOCTYPE html> 
<html> 
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title> Login Page </title>
<style> 
Body {
  font-family: Calibri, Helvetica, sans-serif;
  background-color: pink;
}
button { 
       background-color: #4CAF50; 
       width: 100%;
        color: orange; 
        padding: 15px; 
        margin: 10px 0px; 
        border: none; 
        cursor: pointer; 
         } 
 form { 
        border: 3px solid #f1f1f1; 
    } 
 input[type=text], input[type=password] { 
        width: 100%; 
        margin: 8px 0;
        padding: 12px 20px; 
        display: inline-block; 
        border: 2px solid green; 
        box-sizing: border-box; 
    }
 button:hover { 
        opacity: 0.7; 
    } 
  .cancelbtn { 
        width: auto; 
        padding: 10px 18px;
        margin: 10px 5px;
    } 
      
   
 .container { 
        padding: 25px; 
        background-color: lightblue;
    } 
</style> 
</head>  
<body>  
    <center> <h1> Student Login Form (PRO)</h1> </center> 
    <form>
        <div class="container"> 
            <label>Username : </label> 
            <input type="text" placeholder="Enter Username" name="username" required>
            <label>Password : </label> 
            <input type="password" placeholder="Enter Password" name="password" required>
            <button type="submit">Login</button> 
            <input type="checkbox" checked="checked"> Remember me 
            <button type="button" class="cancelbtn"> Cancel</button> 
            Forgot <a href="#"> password? </a> 
        </div> 
    </form>   
</body>   
</html>
```
However, the server is hosting a *third website* which is still not public since its on it pre-production phase. The server is hosting the website on port *4646* on its *internal network*.
- http://127.0.0.1:4646/login.php
```html
<!DOCTYPE html> 
<html> 
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title> Login Page </title>
<style> 
Body {
  font-family: Calibri, Helvetica, sans-serif;
  background-color: pink;
}
button { 
       background-color: #4CAF50; 
       width: 100%;
        color: orange; 
        padding: 15px; 
        margin: 10px 0px; 
        border: none; 
        cursor: pointer; 
         } 
 form { 
        border: 3px solid #f1f1f1; 
    } 
 input[type=text], input[type=password] { 
        width: 100%; 
        margin: 8px 0;
        padding: 12px 20px; 
        display: inline-block; 
        border: 2px solid green; 
        box-sizing: border-box; 
    }
 button:hover { 
        opacity: 0.7; 
    } 
  .cancelbtn { 
        width: auto; 
        padding: 10px 18px;
        margin: 10px 5px;
    } 
      
   
 .container { 
        padding: 25px; 
        background-color: lightblue;
    } 
</style> 
</head>  
<body>  
    <center> <h1> Student Login Form (PRE)</h1> </center> 
    <form>
        <div class="container"> 
            <label>// * Testear con las credenciales administrator/adm1n$13_2023 (Mismas que las de PRO)</label><br></br>
            <label>Username : </label> 
            <input type="text" placeholder="Enter Username" name="username" required>
            <label>Password : </label> 
            <input type="password" placeholder="Enter Password" name="password" required>
            <button type="submit">Login</button> 
            <input type="checkbox" checked="checked"> Remember me 
            <button type="button" class="cancelbtn"> Cancel</button> 
            Forgot <a href="#"> password? </a> 
        </div> 
    </form>   
</body>   
</html>
```
![[SSRF1.png]]
Nontheless, we can exploit the fact that `utility.php` will include any site including its internal ones :)
We just need to discover what port is the site is being hosted. We'll do such thing with [[ffuf]].
![[SSRF2.png]]
Note that in this case we scanned the *loopback* interface, however there may have been other internal networks as well.