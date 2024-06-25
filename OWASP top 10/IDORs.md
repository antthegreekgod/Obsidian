- **tags:** #top10 #IDOR
# Insecure Direct Object Reference
Insecure Direct Object References (*IDOR*) is a type of security vulnerability that occurs when a web application uses internal identifiers (such as numbers or names) to identify and access resources (such as files or data) and the user's authorization to access them is not properly validated. To exploit an *IDOR* vulnerability, an attacker can attempt to manually modify the identifier of an object in the URL or use an automated tool to try different values. If the attacker finds an identifier that allows him to access a resource that should not be available, then the *IDOR* vulnerability has been successfully exploited.
## Example
We have a website with a drop-down menu where we can select an id ranging from 1 to 5, after selecting a valid number, the website will display an item based on the selection. Let's say we select item number 3; the associated request would be something like: `http://10.0.0.43/xvwa/vulnerabilities/idor/?item=3`
When attempting to *fuzz* for other valid numbers outside the given range we discover that 6-10 are also valid and that the websites displays its respective items. Thus, we have successfully exploited an *IDOR*
`http://10.0.0.43/xvwa/vulnerabilities/idor/?item=10`
### Resource Labs:
[Vulnhub machine](https://www.vulnhub.com/entry/xtreme-vulnerable-web-application-xvwa-1,209/)