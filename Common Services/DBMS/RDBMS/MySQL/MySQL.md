- **tags:** #sql #MySQL #MariaDB #common-services 
- -------------------
# Connect to DB
```bash
msyql -u <username> -h <hostname/IP> -P <Port> -p
```
By default MySQL normally listens on port **3306**.
![[mysql1.png]]
# Navigation
```MySQL
show databases;
use <database_name>
show tables;
describe <tables_name>;
```
# Statements
## Create
- Create a new *database*
```MySQL
create database users;
```
- Create a new *table*
```MySQL
create table logins (
	id int not null auto_increment,
	username varchar(100) unique not null,
	password varchar(100) not null,
	date_of_joining datetime default now(),
	primary key (id)
);
```
As we can see, the pattern to follow when defining the table's columns is:
`<column_name> <data_type> <properties> <default + default value>`
![[my_sql2.png]]
## Drop
- Drop a *table*
```MySQL
drop table logins;
```
- Drop a *database*
```MySQL
drop database users;
```
## Insert
Let's now see how to add a *row* to our tables.
```MySQL
insert into logins values (1, 'ant', 'anthill', '2023/01/01');
```
We don't need to fill the columns for which we set a default value.
```MySQL
insert into logins(username, password) values ('hector', 'supers3cretpassword');
```
Finally, we can also insert multiple values at once.
```MySQL
insert into logins(username, password) values ('marcos', 'password'), ('jaime', 'anotherpass');
```
![[mysql_4.png]]
## Select
- View all content of a table
```MySQL
select * from logins; 
```
![[mysql_3.png]]
- Or we can select the columns which we'd like to see
```MySQL
select username,password from logins;
```
## Alter
We can use *ALTER* to change the name of any table and any of its fields or to delete or add a new column to an existing table.
- We use *add* to add new columns
```MySQL
alter table logins add newColumn int;
```
![[my_sql5.png]]
- We use *rename* to change the column's or table's name
```MySQL
alter table logins rename loginsrenamed; # Change table's name
alter table logins rename column newColoumn to newerColumn; # Change column's name
```
- We use *modify* to change a column's datatype
```MySQL
alter table logins modify newerColumn varchar(100);
```
- Lastly, we can combine it with *drop* to remove a column
```MySQL
alter table logins drop newerColumn;
```
## Update
The *update* statement can be used to change the records of a table based on certain conditions.
- *Example:* Changing the value of the password column for all users which id is higher than 1
```MySQL
update logins set password='change_password' where id > 1;
```
![[my_sql6.png]
# Sorting Results
## Order by
- Choosing a column to order by results. You can either sort the records `asc` or `desc` 
```MySQL
select * from logins order by username;
select * from logins order by username asc, id desc;
```
## Limit
- *limit* the amount of records displayed
```MySQL
select * from logins limit 2;
```
- It is possible to add an *offset* to the filter itself
```MySQL
select * from logins limit 2, 1;
```
## Where
- filter by condition matching
```MySQL
select * from logins where id > 2;
```
- filter by more than one condition
```MySQL
select * from employees where first_name like 'Bar%' and hire_date like '1990-01-01'
```
![[my_sql7.png]]
## Like
- pattern matching search
```MySQL
select * from logins where username like 'ant';
select * from logins where username like 'pe%';
select * from logins where username like '____';
```
- `%`: Wildcard (used to match zero or more characters)  
- `_`:  Match exactly one character
# Operators
In MySQL terms, any *non-zero* value is considered *true*, and it usually returns the value *1* to signify *true*. *0* is considered *false*.
## And / &&
Returns *true* only if the two conditions are met
## Or / ||
Returns *true* if any of the conditions is met
![[mysql_8.png]]
## Not / !
The *NOT* operator simply toggles a *boolean* value ( *true* is converted to *false* and vice versa).
```MySQL
select not 1=1;
# returns 0 (false)
select not 1=2;
# returns 1 (true)
```
Finally, one could use these operators to fine-tune his queries:
```MySQL
select * from titles where emp_no > 10000 || title not like 'Engineer%';
```
## Comments
```MySQL
-- This is a comment (Note the space)
# This is another comment
/** This is an inline comment **/ 
```
# Union Clause
The *Union* clause is used to combine results from multiple `SELECT` statements. The data types of the selected columns on all positions should be the same.
```MySQL
select * from logins union select * from products;
```
# If Function
```MySQL
if(<condition>, <returning value when True>, <returning value when Fasle>)
```
# User Creation
```MySQL
create user 'ant'@'localhost' identified by 's3cretpa@ssword123' # User Creation
grant all priviliges on anthill.* to 'ant'@'localhost' #the user ant has been asigned administrative priviliges throughout the anthill database
create user 'reader'@'localhost' identified by 'p@xssword';
grant select on anthill.* to 'reader'@'localhost'; #the reader user only has the select privilege
```
### Resource Labs
- [SQL Database for practice](https://academy.hackthebox.com/module/33/section/192)