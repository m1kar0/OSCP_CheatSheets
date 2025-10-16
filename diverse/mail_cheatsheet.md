# Pentesting Email

## How email works

* Typically SMTP is served at port 25
* Process for seding and receiving 

`Sender ---SMTP--> Sending Mail Server ---SMTP--> Recv Mail Server ---POP/IMAP--> Receiver`

* Good ressource: https://secybr.com/posts/smtp-pentesting-best-practices/

## SMTP

`sudo python -m smtpd -c DebuggingServer localhost:25`

### Use Telnet to test SMTP


```bash
#source https://learn.microsoft.com/en-us/exchange/mail-flow/test-smtp-telnet?view=exchserver-2019


#Destination SMTP server: mail1.fabrikam.com
#Source domain: contoso.com
#Sender's e-mail address: chris@contoso.com
#Recipient's e-mail address: kate@fabrikam.com
#Message subject: Test from Contoso
#Message body: This is a test message

#This command opens the Telnet session.
telnet

#This optional command lets you view the characters as you type them, and it might be required for some SMTP servers.
set localecho

# establish connection to Sending Mail Server
OPEN mail1.fabrikam.com 25

# get commands available at host server
EHLO contoso.com

# set from mail address
MAIL FROM:<chris@contoso.com>

# set from sender address
RCPT TO:<some@victim.com> 

#get into interactive data input mode
DATA

#this is mail body

Mime-Version: 1.0;
Content-Type: text/html; charset="ISO-8859-1";
Content-Transfer-Encoding: 7bit;

<html>
<body>

<a href="http://scrt.ch/">OCD test</a>

</body>
</html>

#and then press Enter.

#Type a period ( . ) and then press Enter.

#To disconnect from the SMTP server, type QUIT, and then press Enter.

```


### enumerate users for SMTP

* user script `../eMail/vrfy.py`

## POP3 access

```bash
nc 10.11.1.72 -nvC 110 
(UNKNOWN) [10.11.1.72] 110 (pop3) open
+OK beta POP3 server (JAMES POP3 Server 2.3.2) ready 
USER tester
+OK
PASS password1111
+OK Welcome tester
LIST
+OK 2 1807
1 7434
2 11221
.
RETR 1 # to get the mail
```