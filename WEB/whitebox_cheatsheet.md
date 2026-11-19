# White-box web cheatsheet

You have the source and a box you can debug. Stop guessing and read.

The black-box sheet is [[web_cheatsheet]]. This one is the method for OSWE-style work: source in, one exploit script out.

---

## Contents

- [Syllabus map](#syllabus-map)
- [What the exam asks for](#what-the-exam-asks-for)
- [Order of work](#order-of-work)
- [Get the source](#get-the-source)
- [Map the routes](#map-the-routes)
- [Unauthenticated surface](#unauthenticated-surface)
- [Auth and session code](#auth-and-session-code)
- [Sinks by language](#sinks-by-language)
- [Log the database](#log-the-database)
- [Attach a debugger](#attach-a-debugger)
- [Chain shapes](#chain-shapes)
- [What not to do](#what-not-to-do)

---

## Syllabus map

The 24 topics of the WEB-300 syllabus (March 2026) and where each one lives in this vault.

| Topic | Where |
|---|---|
| Web security tools and methodologies | this note |
| Source code analysis | this note |
| Remote code execution | [Chain shapes](#chain-shapes), [Sinks by language](#sinks-by-language) |
| Blind SQL injection | [[web_cheatsheet#SQL injection]], [[Exploit skeleton (Python)]] |
| Data exfiltration | [[web_cheatsheet#SQL injection]], [[web_cheatsheet#XXE]], [[PostgreSQL SQLi to RCE]] |
| PostgreSQL extension and user-defined functions | [[PostgreSQL SQLi to RCE]] |
| UDF reverse shells | [[PostgreSQL SQLi to RCE]] |
| PostgreSQL large objects | [[PostgreSQL SQLi to RCE]] |
| RCE via database functions | [[PostgreSQL SQLi to RCE]], [[web_cheatsheet#SQL injection]] |
| PHP type juggling with loose comparisons | [[PHP Type Juggling and Magic Hashes]] |
| Magic hashes | [[PHP Type Juggling and Magic Hashes]] |
| .NET deserialization | [[Deserialization (.NET)]] |
| JavaScript prototype pollution | [[Prototype Pollution]] |
| Server-side template injection | [[web_cheatsheet#SSTI]] |
| XML external entity injection | [[web_cheatsheet#XXE]] |
| Advanced SSRF | [[web_cheatsheet#SSRF]] |
| Bypassing file upload restrictions and file extension filters | [[web_cheatsheet#File upload]] |
| Bypassing regex restrictions | [[web_cheatsheet#Filter bypass]] |
| Bypassing character restrictions | [[web_cheatsheet#Filter bypass]] |
| Weak random token generation | [[web_cheatsheet#Weak tokens]], [[Exploit skeleton (Python)]] |
| Persistent cross-site scripting | [[web_cheatsheet#XSS]] |
| Session hijacking | [[web_cheatsheet#XSS]], [[Exploit skeleton (Python)]] |
| DOM-based cross-site scripting (black box) | [[web_cheatsheet#XSS]] |
| OS command injection via WebSockets (black box) | [[web_cheatsheet#WebSockets]] |

---

## What the exam asks for

Read the current guide before you plan anything. Points, timings and the list of banned tools change, and blog posts go stale: https://help.offsec.com/hc/en-us/articles/360046869951-OSWE-Exam-Guide

The shape that does not change: targets you may read and debug, an authentication bypass followed by code execution on each, and a script that performs the whole chain by itself. So every finding has to end up as code, and a bug you can only trigger by hand in Burp is half a finding.

Script template: [[Exploit skeleton (Python)]].

---

## Order of work

1. **Get it running and observable.** Source on your machine, query log on, debugger attached. An hour here saves five later.
2. **Map every route.** A list, in a file.
3. **Mark what is reachable without a session.** That is where the auth bypass is.
4. **Read the auth and session code line by line.** Login, reset, remember-me, registration, API keys.
5. **Bypass authentication.** Script it the moment it works.
6. **Now grep for sinks**, with an admin session in hand. Trace each back to a parameter.
7. **Get code execution.** Script it.
8. **Run the whole script against a reverted target.** Twice.

Do the auth bypass before you hunt for RCE. Most code-execution bugs sit behind a login, and knowing you have RCE "once you are admin" is worth nothing until you are admin.

---

## Get the source

Config first. It has the database credentials, the secrets and often the framework version:

```
web.config  appsettings.json  application.properties  application.yml
.env  config.php  wp-config.php  settings.py  config/*.rb  package.json
```

Pull it to your machine and put it under git, so you can grep fast and diff against the vendor's next version:

```bash
ssh user@victim.example 'tar czf - -C /var/www html' > app.tgz
mkdir app && tar xzf app.tgz -C app && cd app && git init -q && git add -A && git commit -qm baseline
```

Compiled stacks:

```bash
# Java: a WAR/JAR is a zip. Own code is in WEB-INF/classes and in the vendor's jars under WEB-INF/lib
unzip -q app.war -d app
java -jar cfr.jar app/WEB-INF/lib/vendor.jar --outputdir src        # CFR
jadx -d src app/WEB-INF/lib/vendor.jar                               # or jadx; jd-gui for browsing

# .NET: the DLLs in bin/. dnSpyEx to browse and debug, ilspycmd to export a project you can grep
ilspycmd -p -o src bin/App.dll

# Python bytecode
pycdc module.pyc > module.py
```

Node and PHP ship as source. Minified front-end bundles: look for the `.map` file before you reach for a beautifier.

If the fixed version of the product is public, diff it. The patch points at the bug:

```bash
diff -ru app-1.2.0 app-1.2.1 | less
```

---

## Map the routes

One grep per framework, saved to a file you can tick off.

```bash
# PHP: every file under the web root is a route, plus whatever the front controller maps
find . -name '*.php' | sort
grep -rnE "(Route::|->(get|post|put|delete|any|match)\()" --include='*.php' .
grep -rnE '\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[' --include='*.php' . | wc -l

# Java
grep -rnE '@(Request|Get|Post|Put|Delete|Patch)Mapping|@Path\(|@WebServlet' --include='*.java' .
grep -nE '<(url-pattern|servlet-class|filter-class)>' WEB-INF/web.xml
grep -rnE 'void do(Get|Post)\(' --include='*.java' .

# .NET
grep -rnE '\[(Route|HttpGet|HttpPost|HttpPut|HttpDelete|AllowAnonymous|Authorize)' --include='*.cs' .
grep -rnE 'MapRoute|MapControllerRoute|MapGet|MapPost' --include='*.cs' .
find . -name '*.aspx' -o -name '*.ashx' -o -name '*.asmx' -o -name '*.svc'

# Node
grep -rnE '\b(app|router)\.(get|post|put|patch|delete|all|use)\(' --include='*.js' --include='*.ts' . | grep -v node_modules

# Python
grep -rnE '@[a-z_]+\.(route|get|post)\(|\bpath\(|re_path\(|url\(' --include='*.py' .
```

---

## Unauthenticated surface

Find the one place that decides "logged in or not", then find what it lets through.

| Stack | Where the decision is |
|---|---|
| Java | `<filter-mapping>` and `<security-constraint>` in `web.xml`; Spring Security `permitAll()` / `requestMatchers`; interceptor `excludePathPatterns` |
| .NET | `[AllowAnonymous]`; `<location path="…">` blocks in `web.config`; `Application_AuthenticateRequest` in `Global.asax`; handlers (`.ashx`, `.asmx`) that never check |
| PHP | the include every page starts with. Pages that do not include it are open |
| Node | middleware order. A route registered before `app.use(auth)` is open |
| Python | missing `@login_required`; DRF `AllowAny`; Frappe `@frappe.whitelist(allow_guest=True)` |

```bash
grep -rLE "(require|include)(_once)?.*(auth|session|login)" --include='*.php' .      # PHP pages without the auth include
grep -rnE 'permitAll|AllowAnonymous|allow_guest|AllowAny|excludePathPatterns' .
```

**Filter and router disagree.** When the filter decides by string (`startsWith("/public")`, `contains("/login")`, `endsWith(".css")`, a regex) and the router then normalises the path, you can satisfy both:

```
/public/..;/admin/users          Tomcat path parameter
/admin/users;.css
/admin/users/.css   /admin/users.json   /admin/users/
/public/%2e%2e/admin/users
//admin/users       /ADMIN/users
```

Then test what the code says against what the server does. Every route, no cookie:

```bash
while read -r p; do
  printf '%s %s\n' "$(curl -sk -o /dev/null -w '%{http_code}' "https://victim.example$p")" "$p"
done < routes.txt | sort | uniq -c -w3
```

Anything that is not a redirect to login or a 401/403 gets read in full.

---

## Auth and session code

Read these, in this order, and ask the question next to each:

- **Login.** How is the password compared? Loose `==` in PHP is [[PHP Type Juggling and Magic Hashes]]. Is the query built by concatenation?
- **Password reset.** Where does the token come from: a CSPRNG, or `rand`, `mt_rand`, `uniqid`, `java.util.Random`, `Math.random`, a timestamp, a hash of things you know? Where is it stored, when does it expire, how is it compared? See [[web_cheatsheet#Weak tokens]].
- **Remember-me and API tokens.** Same questions. Is the value just `user:hash` with a static salt?
- **Session creation.** What goes in the cookie, and what signs it? A hardcoded or default secret means you forge sessions.
- **Registration and profile update.** Does it bind the whole request to the user object? Then `role=admin` goes along (mass assignment).
- **"Internal" shortcuts.** Trust by IP or by header (`X-Forwarded-For`, `X-Real-IP`), debug parameters, setup or install endpoints that still answer, accounts created by the seed SQL.
- **A SQL injection anywhere before login.** It does not need to dump the database. One reset token or one session row is the bypass.

---

## Sinks by language

Grep for the dangerous call, then walk backwards to a parameter you control. Faster than following every input forwards.

```bash
# PHP
grep -rnE '\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function|call_user_func(_array)?)\s*\(' --include='*.php' .
grep -rnE '\b(include|require)(_once)?\b[^;]*\$' --include='*.php' .
grep -rnE '\b(unserialize|extract|parse_str|simplexml_load_string|loadXML)\s*\(' --include='*.php' .
grep -rnE '\b(file_put_contents|fwrite|move_uploaded_file|copy|rename)\s*\(' --include='*.php' .
grep -rnE '(query|prepare|pg_query|mysqli_query)\s*\([^;]*\$' --include='*.php' .

# Java
grep -rnE 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ScriptEngine|parseExpression|InitialContext' --include='*.java' .
grep -rnE 'ObjectInputStream|readObject\(|XMLDecoder|XStream|enableDefaultTyping|new Yaml\(' --include='*.java' .
grep -rnE '(createStatement|executeQuery|executeUpdate|prepareStatement|createQuery)\s*\(' --include='*.java' .
grep -rnE 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|SAXBuilder' --include='*.java' .
grep -rnE 'new File\(|FileOutputStream|Files\.write|transferTo\(|getOriginalFilename|ZipEntry' --include='*.java' .
grep -rnE 'java\.util\.Random|Math\.random|RandomStringUtils' --include='*.java' .

# C#
grep -rnE 'Process\.Start|Assembly\.Load|Activator\.CreateInstance|Type\.GetType' --include='*.cs' .
grep -rnE 'BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|TypeNameHandling|XmlSerializer' --include='*.cs' .
grep -rnE '(SqlCommand|OleDbCommand|ExecuteSqlRaw|FromSqlRaw)\s*\(' --include='*.cs' .
grep -rnE 'XmlDocument|XmlTextReader|DtdProcessing|XmlResolver' --include='*.cs' .
grep -rnE 'SaveAs\(|File\.(WriteAll|Copy|Move|Open)|Path\.Combine|MapPath' --include='*.cs' .
grep -rnE 'new Random\(' --include='*.cs' .

# Node
grep -rnE '\beval\(|new Function\(|vm\.run|child_process|\b(exec|execSync|spawn|fork)\(' --include='*.js' --include='*.ts' . | grep -v node_modules
grep -rnE '\.(query|raw)\(|\$where' --include='*.js' --include='*.ts' . | grep -v node_modules
grep -rnE 'require\([^"'"'"']|res\.render\(|writeFile|createWriteStream|sendFile\(' --include='*.js' --include='*.ts' . | grep -v node_modules
grep -rnE 'merge|extend|defaultsDeep|unserialize|Math\.random' --include='*.js' --include='*.ts' . | grep -v node_modules

# Python
grep -rnE '\b(eval|exec|compile|__import__)\(|os\.(system|popen)|subprocess\.|shell=True' --include='*.py' .
grep -rnE 'pickle\.loads?|yaml\.load\(|marshal\.loads|jsonpickle|render_template_string|Template\(' --include='*.py' .
grep -rnE '\.execute\(\s*(f["'"'"']|["'"'"'].*(%|\+|\.format))' --include='*.py' .
grep -rnE 'extractall\(|send_file\(|os\.path\.join|open\(' --include='*.py' .
grep -rnE '\brandom\.|uuid1\(' --include='*.py' .
```

Two that grep will not show you: `Path.Combine("uploads", name)` in C# and `os.path.join("uploads", name)` in Python both **discard the first part when `name` is absolute**. A filename of `/var/www/html/x.php` or `C:\inetpub\wwwroot\x.aspx` needs no `../`.

---

## Log the database

Send a marker (`zzqq1`), then look for it in the query log. You see exactly how your input lands, quoted or not, and whether the code path even reaches the database.

```sql
-- PostgreSQL (tested on 16)
ALTER SYSTEM SET log_statement = 'all';
SELECT pg_reload_conf();
-- reads: journal or container log, or /var/log/postgresql/postgresql-<ver>-main.log on Debian

-- MySQL / MariaDB (from the documentation)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/tmp/mysql.log';

-- MSSQL (from the documentation): SQL Server Profiler, or the plan cache
SELECT TOP 20 t.text FROM sys.dm_exec_query_stats s
CROSS APPLY sys.dm_exec_sql_text(s.sql_handle) t ORDER BY s.last_execution_time DESC;
```

```bash
tail -f /tmp/mysql.log | grep --line-buffered zzqq1
```

The same trick for the filesystem and for processes:

```bash
inotifywait -mr /var/www /tmp                         # what the app writes
strace -f -e trace=execve,openat -p "$(pgrep -o php-fpm)"   # what it opens and executes
pspy64                                                # processes, no root needed
```

On Windows: Procmon, filtered on the worker process (`w3wp.exe`, `java.exe`) and on `Process Create` / `WriteFile`.

---

## Attach a debugger

A breakpoint at the sink answers in one request what an hour of reading does not: is the line reached, and what is in the variable when it is.

**PHP, Xdebug 3** (port 9003; from the documentation):

```ini
zend_extension=xdebug
xdebug.mode=debug
xdebug.start_with_request=yes
xdebug.client_host=10.10.10.10
xdebug.client_port=9003
```

Restart PHP-FPM or Apache. In VS Code (PHP Debug extension), map the server path to your copy:

```json
{"name": "Xdebug", "type": "php", "request": "launch", "port": 9003,
 "pathMappings": {"/var/www/html": "${workspaceFolder}"}}
```

Xdebug 2 used `xdebug.remote_enable=1`, `xdebug.remote_host` and port 9000.

**Java, JDWP** (tested on JDK 22):

```bash
-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
```

Put it where the JVM is started: `CATALINA_OPTS` in Tomcat's `bin/setenv.sh`, `JAVA_OPTS`, `JAVA_TOOL_OPTIONS`, or the service wrapper's config on Windows. The log line `Listening for transport dt_socket at address: 5005` confirms it. From JDK 9 a bare `address=5005` listens on localhost only, so write `*:5005`.

Attach with IntelliJ (Run → Attach / Remote JVM Debug) with the app's jars added as libraries, so you can set breakpoints inside decompiled classes. Line numbers in exported decompiled source may not match the bytecode; break on methods when they do not.

**.NET, dnSpy** (from the documentation):

1. Run dnSpyEx as Administrator on the target, open the DLLs from the site's `bin`.
2. Debug → Attach to Process → `w3wp.exe`. Several of them? `%windir%\system32\inetsrv\appcmd list wp` maps PID to app pool.
3. Debug → Windows → Modules, and open the module from there: IIS runs a shadow copy under `Temporary ASP.NET Files`, not the file in `bin`.
4. Locals show "optimized away"? Put an `.ini` beside the DLL with the same base name, then recycle the pool (`iisreset /noforce`):

```ini
[.NET Framework Debugging Control]
GenerateTrackingInfo=1
AllowOptimize=0
```

**Node** (tested on Node 20):

```bash
node --inspect=0.0.0.0:9229 app.js        # --inspect-brk stops on the first line
NODE_OPTIONS=--inspect=0.0.0.0:9229 npm start
```

Attach from `chrome://inspect` (Configure → add `victim.example:9229`) or VS Code (`"type": "node", "request": "attach"`). The console there is a REPL inside the app, which is how you check `({}).polluted`.

**Python, debugpy** (tested with Python 3.12):

```bash
pip install debugpy
python -m debugpy --listen 0.0.0.0:5678 --wait-for-client app.py
python -m debugpy --listen 0.0.0.0:5678 -m flask run --no-reload --host 0.0.0.0
```

Turn the auto-reloader off (`--no-reload`, Django `--noreload`), or the debugger attaches to the wrong process.

A debug port bound to localhost is fine: `ssh -L 5005:127.0.0.1:5005 user@victim.example`.

---

## Chain shapes

The combinations that keep turning up. Left column gets you a privileged session, right column turns it into a shell.

| Authentication bypass | then code execution |
|---|---|
| Pre-auth SQL injection → read a reset token or session → log in as admin | file upload with a weak extension filter, or archive traversal into the web root |
| Loose comparison on a token ([[PHP Type Juggling and Magic Hashes]]) | deserialization of a cookie or parameter ([[Deserialization (.NET)]]) |
| Predictable reset token ([[web_cheatsheet#Weak tokens]]) | template injection in something an admin can edit ([[web_cheatsheet#SSTI]]) |
| Stored XSS → the admin's browser performs an admin action ([[web_cheatsheet#XSS]]) | database functions after a stacked query ([[PostgreSQL SQLi to RCE]]) |
| Route outside the auth filter, or filter/router mismatch | command injection in a "test connection", backup or convert feature |
| Prototype pollution setting an admin flag ([[Prototype Pollution]]) | prototype pollution reaching a child process or template engine |
| SSRF or XXE → read a secret → forge a session cookie | plugin, theme or script upload that the admin role is meant to have |
| Mass assignment of `role` at registration | `eval`, dynamic `include` or `require` on a stored setting |

Sometimes one bug does both jobs: a pre-auth deserialization or a pre-auth SQL injection with stacked queries is the whole chain.

---

## What not to do

- **Do not hunt for RCE before you have an auth bypass.** You will find three, all behind the login.
- **Do not read the code top to bottom.** Routes, then auth, then sinks.
- **Do not trust the code over the server.** Curl every route without a cookie. Config and deployment change what is reachable.
- **Do not debug by adding print statements** when a debugger attaches in two minutes.
- **Do not skip the query log.** It shows the injection, and it shows when you are not reaching the database at all.
- **Do not leave the script for the end.** Each stage goes into it as soon as it works.
- **Do not test only on a dirty target.** Revert and run the script from zero; state you created by hand hides missing steps.
- **Do not fire gadgets you have not tried locally.** A deserialization payload or a pollution key that crashes the app costs you a revert.
- **Do not copy version-specific payloads blind.** Check the runtime and library versions first; every deep-dive note states what it was tested on.
