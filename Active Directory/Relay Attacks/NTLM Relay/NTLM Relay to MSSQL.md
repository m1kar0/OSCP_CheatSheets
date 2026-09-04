**NTLM relay to MSSQL** — MSSQL is Microsoft's SQL Server database. When a SQL client logs in to your machine, its NTLM authentication is buried inside TDS (Tabular Data Stream, the wire protocol SQL Server speaks), so standard tools like `ntlmrelayx` cannot relay it directly. The fix is a small forwarder that pulls the NTLMSSP messages out of the TDS packets and hands them to `ntlmrelayx` over HTTP, which relays them on to any of the usual targets (LDAP, ADCS, SMB).

```
SQL client -> attacker: NTLM wrapped inside TDS
forwarder: extract NTLMSSP from the TDS stream
forwarder -> ntlmrelayx: NTLMSSP over HTTP
ntlmrelayx -> target: relay to LDAP / ADCS / SMB
```

## Exploitation

The workaround is a small relay helper that extracts the NTLMSSP blobs from the SQL TDS stream and forwards them to `ntlmrelayx` over HTTP, so the authentication can be relayed to any of the usual targets (LDAP, ADCS, SMB, ...).

The helper listens for the inbound MSSQL connection, pulls the `NTLMSSP` messages out of the TDS packets, and hands them to a running `ntlmrelayx` HTTP listener:

```bash

# 1. Start ntlmrelayx targeting the service you want to relay to (HTTP listener)
ntlmrelayx.py -t 'ldaps://DC_IP' --no-smb-server --http-port 8080 --delegate-access

# 2. Run the TDS->HTTP forwarder in front of it so the MSSQL NTLM blobs reach ntlmrelayx
#    (extracts NTLMSSP from TDS and forwards to http://127.0.0.1:8080)

```

Then coerce/wait for the SQL client to authenticate (see [Coercing Authentication](../../Coercion/Coercing%20Authentication.md)).

## References

- ntlmrelayx.py - https://github.com/fortra/impacket
- The Hacker Recipes - NTLM Relay - https://www.thehacker.recipes/ad/movement/ntlm/relay
