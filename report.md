---
output:
  pdf_document: default
  html_document: default
---
# COMP210 	
# Assessment 01: Security Report

## Members: 	
- Jack MacCormick: 2148113
- Hayden Knox: 2485875


# Summary of the system: 
This website is a product catalog system which provides computer system users a platform for ecommerce, exchanging digital currency in the acquisition of domestic materials. Including canned food provisions, dietary supplements, and cleaning products. 
The system's various components are as follows:
- web-catalogue
- account creation
- account logins
- images

User information confidentiality is maintained by employing a two-part authentication system, using a unique _username_ and a paired password authenticate the identity of each user, restricting access to each user's information to only the respective use. The unique username restriction also ensures unique membership, preventing users from accessing another's information or resetting another user's password. Stored passwords are hashed while within the database, so they're not stored in raw-text format. 

Permissions for system users are limited to __user__-table database entry, username and password entry and item table searches.
However, privilidged permissions reserved for only administrator users are inadequately protected, due to lack of enforcement of password entropy requirements and of adherance to common security recommendations.
- User accounts provide access to the logged in section of the website
- search the catalogue feature returns a subset of the larger product table.
- Account creation requires details outlined below:

Field Name:        | User details:
-------------------|---------------
Username:          | -------
Real Name:         | -------
E-Mail:            | -------
Street Address:    | -------
City:              | -------
Credit Card:       | -------
CC Expiry:         | -------
CVV:               | -------
Password:          | -------
Password (confirm):| -------
 

# Vulnerabilities:
## 1)	Passwords: Authetication and Authorization

In our analysis when creating a new account in the system several weaknesses were noticed regarding Account Creation and System User Logins. 

Most significantly is the lack of mechanisms the system uses to secure account access and stronger password creation. This system lacks two factor (2FA) authentication, relying on a single point of authentication; the knowledge of the username and password pair. This does not serve as an adequate measure for user authentication and authorization in the modern era of computing power. The many weaknesses of the system originate from the failure to address various principals of password creation:

__Password Character Length (CWE-521):__
- The minimum amount of required characters to create an account password is 5 alphabetical characters and one numerical character.  This small password length requirement produces a tiny minimum required entropy requirement (a measure of the number of possible combinations of characters making up the password). This low entropy requirement for user passwords dramatically reduces security.
- ![image](https://user-images.githubusercontent.com/80669114/131648017-8f016447-da3f-4efa-996d-cec5f8b05b3d.png)

__Password Attacks: (CVE-2020-14494):__
- Given the very small amount of characters required to qualify for a secure password on the system and the lack of recomendation for different symbols this leaves the systems vulnerable to a series of password attacks, specifically: 

- __Brute Force (CVE-2020-14494):__
    + Brute force attacks apply a recursive entry of numerous password perrmutations and combinations: beginnning with the first character combination "aaaaa". As 5 alphabetical charcters and one numeric character are the minimal requirement, the amount of time required to step through all of these possible password combinations is tiny.

- __Rainbow Table (CVE-2021-21253):__
    + A rainbow table in a brief summary is a precomputed table of the hashed equivalents of known password, produced by various common cryptograpohic hashing functions. This is a much more efficient method of password attacking, demanding less computer processing time as the permutations have already been calculated, but requires more memory to store these known values. 
    + Using a packet sniffer (outlined further on in this report) we are able to see that upon account creation and user authentication, the password that is validated is stored as a 32bit hexidecimal hash. Using linux tools we can hash a given raw text input, to check a known password, and it's equivalent in common 32 bit hexidecimal hashing function output, to what we see being transmitted from the server: 
        * __code:__ [echo -n 'admin' | md5sum] returns "21232f297a57a5a743894a0e4a801fc3" 
        * ![image](https://user-images.githubusercontent.com/44104639/132082291-c62d300b-3414-41e8-b853-cba2188d0586.png)
    + From this matching output of the known text "admin" to "21232f297a57a5a743894a0e4a801fc3", and the sniffed data containing the password hash "21232f297a57a5a743894a0e4a801fc3", we know the hashing algorithm is md5. Knowing which hashing algorithm is being used reduces the complexity of creating and running a rainbow table attack, as attackers only have to create and compare the stored results with the outputs of one hashing function, rather than those of many. 
    + Using a rainbow table attack, malicious parties can scan over the database for hashed character matches to known hashed versions of dictionary terms and commonly used passwords, identifying any passwords in the database included the rainbow table. From this, attackers would have user's passwords in rawtext, and all associated user details, including email addresses, giving attackers access to user accounts on the system and potentially access to 3rd party sites where the users have also used those creditials.
    + An example of this type of attack is shown below in section "CWE-916: Use of Password Hash With Insufficient Computational Effort"


__No Salt Usage (CVE-2021-32596)/CVE-2019-25030/CWE-759:__
- _The passwords string hashes do not use a salt password for encryption. Attackers can generate and use precomputed hashes for all possible password character combinations (commonly referred to as "rainbow tables")_

The passwords string hashes do not use a salt password for encryption. Salts are a random string which is concatenated to passwords before the hashing algorithm md5 is used. With each salt string being unique for each individual password.

In knowing the encryption algorithm (MD-5) which is used to encrypt the user passwords, we can find corresponding matches to database entries by doing a simple entry of a dictionary of terms into an md5 hasing program. By including a salt, these dictionary terms would be modified, and thus produce a different hash, making brute force attacks much slower, and rainbow table attacks impossible, making cracking user password hashes exponentially more difficult and time consuming.
- No Pepper Usage: 
    + A pepper is an additional single random string, much like a salt, but which is not stored in the databse as salts are. In the event that a database is accessible and hashes values are compromised, the use of external peppers in the hash creation makes determining the original password value effectively impossible.

__CWE-916: Use of Password Hash With Insufficient Computational Effort__
- _If an attacker can obtain the hashes through some other method (such as SQL injection on a database that stores hashes), then the attacker can store the hashes offline and use various techniques to crack the passwords by computing hashes efficiently. Without a built-in workload, modern attacks can compute large numbers of hashes, or even exhaust the entire space of all possible passwords, within a very short amount of time, using massively-parallel computing_

In combination with the SQL insert attacks detailed more below, we are able to conduct an offline bruteforce attack, using rainbow tables, to produce hashes which can then be compared against the stored hashed passwords. Knowing the hashing algorithm, and it only being 32 bits long means the work required to do this is relatively low.
- ![image](https://user-images.githubusercontent.com/80669114/131611110-6d99c727-c32a-4911-b01e-d6f9918f5733.png)
- ![image](https://user-images.githubusercontent.com/80669114/131611063-393741a2-e2c8-4a2d-a2b6-31dda30236c4.png)
- Sources for rainbow table contents:
    + https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
    + https://www.bragitoff.com/2016/03/english-dictionary-in-csv-format/

Data Exfiltration with filewrite: Through an injection attack who's method is described below, the CVV field allows us to execute code which creates a file version of the __USER__ table, which we can then download. This file gives us unrestricted access to all fields in this table, revealing the street addresses of users, their real names, their email addresses, and all details of their added credit cards. In addition, hashed passwords also are in this file, which can be cracked as outlined above.

Having both the rawtext (cracked) passwords and the email addresses of users potentially allows us access to 3rd party sites, where those creditials may have been reused.
From a rainbow table created from the top 10,000 passwords and the english dictionary, we were able to crack 244 accounts within the database of 1091 users:
- ![image](https://user-images.githubusercontent.com/80669114/131611164-3a4a5420-dbba-4308-927c-58ecf17b913e.png)

__Poor Password Policy (CWE – 521 : Weak Password Requirements)__
Security controls and mechanisms to enforce a more secure password policy are lacking, and have not been consistently applied: the minimum amount of required characters to create an account password; minimum of 5 alphabetical characters and one numerical character, has not been consistently applied to all users in the database. This further reduces the entropy of their passwords, reducing security.
- __CAPEC-70: Try Common or Default Usernames and Passwords:__
- _Security controls and Mechanisms used to enforce a more secure password policy are lacking in addition to being inconsistent. L2 with this lack of secure policy password enforcement the likely hood of human error creating many more weak passwords for user accounts increases_. L2/S33. _"A computer is only as secure as the administrator, technical support, or policies are trustworthy naïve"._ 
- Using an informed brute force search the administrator password has been cracked and now accessed in the system L4/6S5
  + The admin user's password is the default setting: [user=admin, password=admin]
  + This allows unauthorised actors to get access to administrator versions of the site. While there is currently no additional privilidges are provided to the administrator on this system, it represents a critical issue for digital systems generally.
  + ![image](https://user-images.githubusercontent.com/44104639/132082204-38e5cc64-473c-4cb3-af94-63dae0468ded.png)
  + ![image](https://user-images.githubusercontent.com/44104639/132082167-a68e6069-1013-41c4-b801-bafab14f2af5.png)
  
### Mitigation: 
Recomendations:
- We recommend that the system impliment a more effective passoword and username policy. To more striclty adhere to security standards that prove to bee more secure and less vulnrable to common attack methods. The recommened 80 bits of binary entropy be met for passwords and that all username keys should incorperate at least one capital letter and two numbers. The following criteria for passwords can be implemented to meet the 80 bits of binary entropy:

- User Passwords: Entropy Options:
    + Each password can have 18 random lowercase characters 
    + Each password can have 15 random upper/lowercase characters
    + Each password can have 14 random uppercase/lowercase/number characters
    + Additionally we can: 
        * Automatically generate strong passwords for users
        * Delete all default account credentials that may be put in by the product vendor, i.e. default administrator creditials.
        * prompt users every once in a while that new password must be chosen, to prevent aging
        * use a two-factor authentication system
        * passwords should be hashed using all of; Salt, pepper, plaintext password

Not addressing these issues poses a threat to:
- People
- Data 
- Information Systems infrastructure


## 2) Network-level Security: 
When using tomcat to verify and examine the network security of the system it became clear that the website server was using the HTTP protocol which presents a number of security vulnerabilities and exposure of client-side information. 

__Lack of HTTPS: (CWE-319: Cleartext Transmission of Sensitive Information):__
- _The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors. Many communication channels can be "sniffed" by attackers during data transmission. For example, network traffic can often be sniffed by any attacker who has access to a network interface. This significantly lowers the difficulty of exploitation by attackers._

With the Lack of HTTPS usage for this system is leaves a vulnerability to packet sniffing. 
As HTTP is a stateless protocol, being a configuration of system memory. Client-side information is used to validate repeat access attempts. With the exposure of cookie information, malicious parties can use hackjacked client session data to bypass authentication steps.
- Further, these cookies can be used for storing user preferences and user tracking. 
- ![image](https://user-images.githubusercontent.com/44104639/132082266-25a1599c-1be6-49ab-8681-2dcc8d040d49.png)
- ![image](https://user-images.githubusercontent.com/44104639/132082384-e4504269-2b73-4ea7-8371-2d9d4039102c.png)


__Packet Sniffing (CVE-2018-1843):__
- _does not use a secure channel, such as SSL, to exchange information only when accessed internally from within the cluster. It could be possible for an attacker with access to network traffic to sniff packets from the connection and uncover data._

From first examination the user's session data is unencrypted and exposed in transit, data including a person’s username  identifier, password string and the hashed password, allowing us to deduce the hashing algorithm used to encrypt user passwords.
It was this lack of encryption that allowed us to determine the hashing algorithm used to protect user's passwords, and which dramatically increased the viability of a rainbow table attack.

### Mitigation: 
- One basic mitigation is to use HTTPS for all transactions that involve cookies or other sensitive data. 
- Most browsers also provide an easy interface by which users can view, manage and delete cookies, this should be done automatically fairly often. 
- Restricting the availability of the cookie to specific domains (such as the origin only) and limiting the cookie lifetime can also be reduce the risk of certain types of cookie abuse.

## 3) Path Traversal Flaws: Authentication and Authorization
Given the lack of pages and functionality behind login-walls, path traversal flaws seem to be mitigated and do not pose an immediate threat to the network. 

## 4) SQL Inserts
- __CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')__
- __CWE-20: Improper Input Validation (more generally)__
    + _Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data. This can be used to alter query logic to bypass security checks, or to insert additional statements that modify the back-end database, possibly including execution of system commands._

The CVV field of the Account Creation page allows SQL code to be executed within the server from the front-end-user interface. This provides the ability to modify and delete data values within the associated __USER__ table. This is not limited to only content within the CVV field, it allows us full access to any field in this table, including the hashed passwords of the users, which is another vector for us to deduce the hashing algorithm used.
-  __code:__ memed');   UPDATE USER SET NAME = 'hello you' WHERE USERNAME='admin';--

Using this method we would be able to modify the user data, replace it with encrypted versions of the data, in a way analogus to a ransomware attack, or to DROP the entire table. 

This access is not limited to just the __USER__ table. We are also able to access other tables, such as the __PRODUCT__ table, which is diplayed on the catalogue page of the website. As such, we can set values within the catalogue, i.e. STOCK and PRICE, providing a vector to interfere in serivce delivery without totally preventing access to the webstore, through a Denial of Service attack (DoS).

__CWE-200: Exposure of Sensitive Information to an Unauthorized Actor:__
- _The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information._

SQL insert attacks also allow us to access the invidiual __USER__ table and write out databases to a file, and to the tomcat serve the site is hosted on, which allows attackers to exfiltrate the systems' various tables, including the __USER__ table, which includes:
- Username
- Real Name
- E-Mail
- Street Address
- City
- Credit Card
- CC Expiry
- CVV
- hashed password (shown to be breakable)

This attack violates the privacy controls typically enforced through user idenitificaition and authentication and is sufficent to not only access this site, but to also access other sites where user creditials are recycled, and to complete credit card transactions as any user in this table. Further, their physical location is also revealed to attackers.
- __code:__ memed'); CALL CSVWRITE('/home/tomcat/apache-tomcat-9.0.52/webapps/catalogue/hackerman.csv', 'SELECT * FROM PUBLIC.USER');--
- This creates a CSV file on the hosting webserver, which can be accessed at the domain: server: _localhost:8080/catalogue/hackerman.csv_ (generic format: _webaddress/catalogue/hackerman.csv_)

### Mitigation:
- Input sanitisation: preventing malicious users from being able to write execute scripts/code lines
- specific text characters should be removed or prohibited from being input by users. Characters such as: =, ;, |, and *.  

## 5) Javascript Inserts - Second order SQL inserts:
__CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')__
_The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users._

Specifically we will demonstrate a _Type 2: Stored Cross-Site Scripting (XSS) (or Persistent)_ attack, using inserted Javascript: _At a later time, the dangerous data is subsequently read back into the application and included in dynamic content. From an attacker's perspective, the optimal place to inject malicious content is in an area that is displayed to either many users or particularly interesting users_

Through the SQL insert vector of the _account creation CVV_ field, we are also able to upload Javascript code into the SQL database. This javascript is then executed when the website is rendered in a user's browser, allowing us to influence the website display of OTHER users, which constitutes a secondary insert attack.
One of the features in the webpage, is the welcome _user_ message, which displays the real name of the user, drawn from the database. As this field is displayed to each user, replacing this datafield with script code allows us to affect the interactions of all users. 

__CWE-601: URL Redirection to Untrusted Site ('Open Redirect')__
- _A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL. By modifying the URL value to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials._

Through this feature and the SQL + Javascript injection vulnerability, we are able to prompt logging in users with a pop-up which prevents their access to the website, and instead presents them with a prompt of our choosing. This link could point to a "replicate" of the original site, allowing us to collect usernames and passwords in rawtext form as these users attempt to login to the replicate site:
- __code:__ memed');  UPDATE USER SET NAME = '<script>alert("Session timed out.  Please log in to continue.");window.location="https://www.youtube.com/watch?v=dQw4w9WgXcQ"</script>' ;--
- ![image](https://user-images.githubusercontent.com/80669114/131648907-50578662-e2e0-461e-92d1-367c7dab6d37.png)

As this real name is shown on every page of the site once a user logs in, it will effectively enact a Denial-of-Service on anyone who logs in, preventing all subsequent interactions until the browser's JSESSION cookies are cleared, or until the user makes a new account as this new account will not have been effected by the database modifying insert attack yet.

Further, as the SQL insert allows us to modify other tables, we can preform wider a DoS attack, preventing interactions, even for someone who has not logged in. By modifying a field within the catalogue table, we can prevent users from being able to view the catalogue of the webstore:
- __code:__ memed');  UPDATE PRODUCT SET DESCRIPTION  = '<script>alert("Session timed out.  Please log in to continue.");window.location="https://www.youtube.com/watch?v=dQw4w9WgXcQ"</script>';--    

