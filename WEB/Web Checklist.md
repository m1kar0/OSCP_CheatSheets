

## Discovery

- [ ] Find the ASN related to the audit.
- [ ] Find all subdomains and domains related to the audit. [[03 - DNS enumeration|DNS enumeration]]
- [ ] Find all the IPs related to the audit.
- [ ] If in scope, check for subdomain and domain takeover.
- [ ] Scan all the exposed ports related to the audit and analyse each service.
- [ ] Stay in the scope.
- [ ] If behind WAF/DDoS protection (Cloudflare/Akami/...), try to find original IP of the servers (historical DNS data, information disclosure in the application, scan company IPs).
- [ ] If huge scope, it is advised to use automatic tools to at least screenshot the servers (eyewitness / gowitness, ..)
- [ ] Check SSL configurations

## Discovery - OSINT like

- [ ] Find any OSINT related data that could be useful for the audit.
- [ ] Find more secrets, hosts, informations through tools (wayback, google dork, ...)
- [ ] Find any employee leaked credentials to test on the login panels.
- [ ] Find employee/company's Github or developer repositories and looks for source code and secrets.
- [ ] Find third party accounts of the targeted company (Facebook, Linkedin, ...) if in scope.

## Unauthenticated

For each service:
- [ ] Find the application and software version, looks for outdated components and their related CVE.
- [ ] Find login panels and use leaked credentials or default passwords. Password bruteforce could also be used if it doesn't break the accounts nor the applications.
- [ ] Analyse the code of the HTML/JS/CSS and looks for secrets, endpoints, vulnerabilities ... etc. Verify the existence of JS source maps.
- [ ] Check if the server is vulnerable to any HTTP request smuggling attacks.
- [ ] Check if the server is vulnerable to any race condition attacks.
- [ ] Check how the server handle additional HTTP headers (X-Forwarded-For, ...)
- [ ] Check if the server load external contents (links, scripts), and if the external contents can be controlled.
- [ ] Try to discover files and folders. (normal files, backups, .git folder, ...) [[03 - Files & Folder discovery]]
- [ ] Send faulty request and check for stacktraces.
- [ ] Check if the servers are running in debug mode.
- [ ] Check for HTTP security header (Clickjacking, CSP, ... )
- [ ] Check TRACK/TRACE HTTP verbs
- [ ] For each service, find if the source code or firmware is available (open source, leak, provided by customer, ... etc). If the time allows, perform [[01 - Code review|code review]] or reversing. 


## Registration

- [ ] Check for injections: SQLi, noSQLi, json/xml parsing bugs, ... 
- [ ] Check for second order injection that will be trigger on the website afterward: name, email, ... -> XSS, OS command injection, SSTI, ...
- [ ] Check for second order injection that will be triggered in the email registration: name, email, ... -> HTML injection, SSTI, ...
- [ ] Check for user enumeration
- [ ] Check registration bruteforce (don't break)
- [ ] Check URL redirect -> Open redirect

## Login

- [ ] If OAuth, check any OAuth related vulnerabilities.
- [ ] If third-party SSO, check any related vulnerabilities.
- [ ] Uses leaked credentials or default passwords. Password bruteforce could also be used if it doesn't break the accounts nor the applications.
- [ ] Analyse the login process and verify if the account name or id can be altered during the login for ATO.
- [ ] Check for injections: SQLi, noSQLi, json/xml parsing bugs, ... 
- [ ] Check for login/registration/password reset with injection in HTTP headers or variable (Host, X-Forwarded-For, ...).
- [ ] Check for user enumeration
- [ ] Check login bruteforce (don't break)
- [ ] Check URL redirect -> Open redirect
- [ ] If 2FA, check 2FA bypass techniques [[03 - Web 2FA]]

## Password reset

- [ ] Check for login/registration/password reset with injection in HTTP headers or variable (Host, X-Forwarded-Host, ...).
- [ ] Check how the reset is handled
- [ ] Check content of reset token
- [ ] Modify a byte or the length of the token and see if an error about a cipher used is returned
- [ ] Check reset token generation attacks (race condition)
- [ ] Check password reset bruteforce (don't break)

## With accounts

- [ ] Analyse the roles of the provided accounts in the application. Check for any missing access control (privileged feature reachable with an unprivileged account or unauthenticated).
- [ ] Analyse security of the session cookies (secure/samesite/HttpOnly/domain).
- [ ] Check for CSRF
- [ ] Analyse the content of the session cookies, if not a random value.
- [ ] Check if the sessions can be fixed.
- [ ] Check if the session can be reused on other service/server/application.
- [ ] If JWT, check for JWT related vulnerabilities
- [ ] If SAML, check for SAML related vulnerabilities
- [ ] Check if the session is invalidated when logged-out (usually a problem with JWT), and also after the real expiration timestamp.
- [ ] If ViewState, check ViewState related vulnerabilities



## Manual inspection

#### Input validation

- [ ] Check for SSTI / SSI / ESI
- [ ] Check for reflected XSS
- [ ] Check for stored XSS
- [ ] Check for DOM XSS
- [ ] Check for Universal XSS
- [ ] Check for HTML injection in PDF generation (could cause LFI or SSRF)
- [ ] Check for command injection (\`;|&)
- [ ] Check for deserialisation
- [ ] Check for XML / JSON conversion of the body
- [ ] Check for XXE in any XML like
- [ ] Check for CRLF injection
- [ ] Check Xpath injection
- [ ] Check header injection
- [ ] Check LDAP injection
- [ ] Check for mass assignment vulnerabilities (modify object attributes that should not be accessible / modifiable)
#### File upload

- [ ] Check for upload of html/xml/svg -> XSS
- [ ] Check for upload of CGI files (php, cgi, xhtml, ...)
- [ ] Check for bypass of file extension
- [ ] Check for upload of "malicious" file EICAR
- [ ] Check for image processing vulnerabilities (e.g. conversion from SVG could allow including local files)
#### File download / resource retrieval

- [ ] Check for SSRF
- [ ] Check for IDOR
- [ ] Check for LFI / arbitrary file download
- [ ] Check for Path traversal
- [ ] Check for input validation vulnerabilities in the filename
#### API

- [ ] Check CORS
- [ ] Check CSRF
- [ ] Check for IDOR
- [ ] Check for access control issues
- [ ] Find other endpoints
- [ ] Uses different Verb or URL path to bypass access control
- [ ] Check for race condition
- [ ] Check for all input validation vulnerabilities
- [ ] Check for JSON and related vulnerabilities (encoding, parameter pollution, JSON entities dict list etc, ...) 
- [ ] Check for SOAP and related vulnerabilities
- [ ] Check path traversal in input and URL
#### Cache

- [ ] Check for cache poisoning vulnerabilities
- [ ] Check for cache issues