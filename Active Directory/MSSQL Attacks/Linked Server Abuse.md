**MSSQL linked-server abuse** — MS SQL servers are common on domain hosts and often trust domain accounts. Authenticate with domain creds/PtH, then abuse in-database features to escalate or move laterally: follow **linked-server** chains (`EXEC ... AT [LINKED]`), impersonate logins (`EXECUTE AS`), and get code execution (`xp_cmdshell`). MSSQL can also be coerced/relayed.

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
