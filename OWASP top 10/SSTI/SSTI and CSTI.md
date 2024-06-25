- **tags:** #top10 #SSTI #CSTI
- ------------------
# Server Side Template Injection
Template engines are designed to generate web pages by combining fixed templates with volatile data. Server-side template injection attacks can occur when user input is concatenated directly into a template, rather than passed in as data. As the name suggests, server-side template injection payloads are delivered and evaluated server-side, potentially making them much more dangerous than a typical client-side template injection.
Common Template Engines:
- **PHP**: Smarty, Twig
- **Java**: Velocity, FreeMarker
- **Python**: Jinja, Mako, Tornado
- **JavaScript**: Jade, Rage
- **Ruby**: Liquid
## Detection
Perhaps the simplest initial approach is to try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\`. If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way.
## Example
We've got a website which [[http service#whatweb|whatweb]] recognizes Python running on the back end and we see that user input is processed to then be displayed. It may arise the suspicion that there's indeed a template engine being used to dynamically display the web content. We over to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) and start trying its payloads for Python's templates. We finally see how the site is vulnerable to the *Jinja2* (Jinja2 is used by Python Web Frameworks such as Django or Flask) payloads and finish by gaining *RCE*.
![[SSTI1.png]]
![[SSTI2.png]]

# Client Side Template Injection
Client-side template injection vulnerabilities arise when applications using a client-side template framework dynamically embed user input in web pages. When a web page is rendered, the framework will scan the page for template expressions, and execute any that it encounters. An attacker can exploit this by supplying a malicious template expression that launches a cross-site scripting (XSS) attack. As with normal cross-site scripting, the attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.
### Resource Labs
- [SSTI Jinja](https://github.com/filipkarc/ssti-flask-hacking-playground)
- [CSTI, git clone; cd skf-labs/python/CSTI; pip2 -r install requirements.txt; python2 CSTI.py](https://github.com/blabla1337/skf-labs)
- [Perfection HTB Machine](https://app.hackthebox.com/machines/Perfection)
- [GoodGames HTB](https://app.hackthebox.com/machines/446)