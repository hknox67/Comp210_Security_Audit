# COMP210 Assignment 01 - PLAN
#### Author:
    Jack MacCormick -   2148113
    Hayden Knox     -   2485875

## Possible vectors:
- What is the databse? H2 (need info schema)
- Can we get into the database - is there stuff displaying special to each user?
- can we navigate between users, using some token/address manipulation?
- can we extract the databse?
- can we brick/drop the databse?
- do default admin creds work?
- can we get in without any creds?
- can we increases the privilidges of a user?
- can we path traversal throughout the system?
- can we change the domain links within the system point to?

#### if exfiltrated:
- are the entries in raw text?
- are they encrypted?
- are they hashed (and salted)?

## First thoughts on the webclient:
- it's a shop
    + web-catalogue
    + account creation
    + account logins
    + images
- catalogue has an text-entry field
    + search returns the search term as a string
- catalogue is a big table
- passwords must bce 5 char long, and include 1 digit 
    + 00001 is not valid, so not 5 chars, but 5 somethings? or it's truncating ints
    + it's not santistising passwords
- packet sniffing is possible, so it's not HTTPS, just base HTTP.

## First thoughts on the H2 database:
- we're given acccess to the database so we can see what's going on.

## Made an account:
- user:                 stevie
- email:                stevie@me.com
- name:                 stevie
- street address:       123
- city:                 washington
- card:                 0000000000000000
- CVV:                  000
- exp:                  01/01
- Password:             hi0001
- Password (confirm):   hi0001

### Made another one, to test how authorisation and privilidge is given:
- user:             admin
- doesn't give us admin privilidges, worth a shot.

## Logging in as someone else:
- [user=admin, password=password]       :   doesn't work
- [user=admin, password=password1]      :   doesn't work
- [user=administor, password=password]  :   doesn't work
- [user=admin, password=admin]          :   works
    + Displays the name Administrator on the webpage upon logging in. I haven't entered that word yet, so it's taking something from a database.
- sends you to this domain if login is rejected: "awesome_login.jsp?login=fail"
    + changing this to "=success" is a valid domain, but doesnt seem to do anything. Doesn't log you in as the user who's username we entered. 

## SQL Insert attempts:

### Catalogue search entry:
- only searches the PRODUCT_DESCRIPTION column, not ID# or price
- doesn't allow direct code injection

### Login screen:
- username: [food<script>document.body.style.backgroundColor='#FF0000'</script>] 
    + Changes the background colour of the webpage, meaning the system is not santistising strings
- username: [<script>alert(document.cookie)</script>] 
    + does create an alert
- username: [food<br/><a href="https://i.chzbgr.com/maxW500/4554986496/hF3327748/">Back</a><!--]
    + this works, so can redirect the page locally. 
        * if this script code is put into the database with SQL inserts we could redirect other users to a 3rd party site, possibly one which is a "replicate" of the original site, so we can collect usernames and passwords in rawtext form as these users attempt to login to the replicate site.
- This isn't putting our code into the database, so we need to do something with the account creation feature.

### Create account structure:
- Username:             -------
- Real Name:            -------
- E-Mail:               -------
- Street Address:       -------
- City:                 -------
- Credit Card:          -------
- CC Expiry:            -------
- CVV:                  -------
- Password:             -------
- Password (confirm):   -------

#### DROP TABLE through password field:
- Does not execute the SQL command, because it hashes the password BEFORE it's added to the table

### DROP TABLE through the Credit Card field:
- Generates a SQL syntax error in the H2 server logs, but tells webclient-user that an account has been created. 
- Because of this SQL error, the account isn't created and does not appear in the database.

### DROP TABLE through the CVV field:
- This works! Having the ability to delete the user table means we can modify and delete data values within the user table. This is not limited to only content within the CVV field, it allows us full access to any field in this table, and other tables: i.e.
    + memed');   UPDATE USER SET NAME = 'hello you' WHERE USERNAME='admin';--
    + this allows us to change the values of other users
- We are also able to insert script code into the database, allowing us to influence the website display of OTHER users, which is a secondary insert attack.
- One of the features in the webpage, is the welcome user message, which displays the real name of the user, which is drawn from the database. As this field is displayed to all users, replacing this datafield with script code allows us to affect the interactions of all users. 
    + as this real name is shown on every page of the site once a user logs in, this will effectively Denial-of-Service anyone who logs in, preventing all subsequent interaction while until JSESSION cookies are cleared, or until the user makes a new account, which will not have been effected yet 
    + memed');  UPDATE USER SET NAME = '<script>alert("Session timed out.  Please log in to continue.");window.location="https://www.youtube.com/watch?v=dQw4w9WgXcQ"</script>' ;--

- As this insert allows us to modify other tables, we can preforma a DoS attack, preventing interactions, even for someone who has not logged in:
    + by modifying a field within the catalogue table, we can prevent users from being able to view the catalogue of the webstore:
    + memed');   UPDATE PRODUCT SET DESCRIPTION  = '<script>alert("Session timed out.  Please log in to continue.");window.location="https://www.youtube.com/watch?v=dQw4w9WgXcQ"</script>';--    
- Further, we can also allows set values within the catalogue, i.e. STOCK and PRICE. This allows us to affect users, even if we don't wish to totally prevent access to the webstore.

## Packet sniffing:
- With the use of a packet sniffer, we can see the sent login details and account creation fields, including the raw and hashed password of a user. This allows us to see what the length of the hashed password is.
    + we known that "admin" maps to "21232f297a57a5a743894a0e4a801fc3"
    + 32 long hash
    + if we can find a 32 bit long hexidecimal hashing algorithm which matches admin to the above hash, we will know which one they use to secure the stored passwords.
        * using linux tools; [echo -n 'admin' | md5sum] returns "21232f297a57a5a743894a0e4a801fc3"
        * from this match, we know the hashing algorithm is md5
    + using a rainbow table (for md5), we could scan over the database for known hashed versions of dictionary terms and commonly used passwords, allowing us to identify any passwords in the database which are also in the rainbow table. From this, we would have user's passwords, and their email from their account info, giving us access to their account, and potentially giving us access to 3rd party sites using the same creditials.




## WORK SPACE

- Script execution means we should theoretically be able to exfil any table within the database to an external site, upon anyone querying the database where that script lies.
    + step 1: create a script which would write out the desired table to an external site
    + step 2: create an SQL insert line which sets a specific USER's name to the webscript as described in step 1. Using a where clause ensures we don't override the data we want to exfil; 
        + script: any text');   UPDATE USER SET NAME = '_exfil script here_' WHERE USERNAME='hackerman';--
    + step 3: create a new user account, entering the SQL script in the CVV field
    + step 4: login as this newly created user, causing the website to attempt to display the user's name, which instead is our script, which will then be executed. 
