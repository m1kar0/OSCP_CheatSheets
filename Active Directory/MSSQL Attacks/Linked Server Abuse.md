**MSSQL linked-server abuse** — Microsoft SQL Server runs on many domain machines and often accepts Windows authentication — though that alone does not hand a random domain user a session: access needs a SQL login mapped to your account or one of your groups (common on misconfigured targets). Where you do get in, you can turn the database engine itself into a foothold to escalate privileges or jump to other hosts. A linked server — a saved connection one SQL server keeps to another so it can query it — lets you run queries (and often OS commands) on that second box as if you were sitting on it, and chaining these links hops you from server to server. Mechanically: authenticate with domain creds or pass-the-hash, then follow **linked-server** chains (`EXEC ... AT [LINKED]`), impersonate a more powerful login with `EXECUTE AS`, and get code execution through `xp_cmdshell`. You can also coerce the SQL service account into authenticating to you (via UNC paths / `xp_dirtree`) and capture or relay that login.

```
You -> SQL-A       (domain creds / pass-the-hash)
SQL-A -> SQL-B     EXEC('...') AT [SQL-B]   (linked server)
SQL-B -> SQL-C     next link in the crawl
on target: EXECUTE AS sa -> xp_cmdshell -> OS command
```

## TODO

Placeholder - full write-up pending. Should cover:
- Discovery/auth: `mssqlclient.py 'DOMAIN/USER:PASS@TARGET' -windows-auth`; NetExec `nxc mssql`; PowerUpSQL `Get-SQLInstanceDomain`.
- Linked servers: `enum_links` / `EXEC ('...') AT [LINKED]`, multi-hop chains (PowerUpSQL `Get-SQLServerLinkCrawl`).
- Privilege: `EXECUTE AS LOGIN='sa'`, trustworthy-db abuse; enable + run `xp_cmdshell`.
- UNC-path / `xp_dirtree` coercion → capture/relay the service account's auth (link to Coercion / NTLM Relay to MSSQL).

## References

- The Hacker Recipes - MSSQL - https://www.thehacker.recipes/ad/movement/mssql
- PowerUpSQL - https://github.com/NetSPI/PowerUpSQL
- HackTricks - Pentesting MSSQL - https://hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html
