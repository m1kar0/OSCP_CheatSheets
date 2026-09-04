**PingCastle** — a tool that scans a whole Active Directory domain and grades its security posture, flagging common misconfigurations (weak trusts, stale accounts, dangerous permissions) in a single HTML report. Point it at any reachable DC — even from a non-domain-joined machine — run `--healthcheck`, and read the report for a fast "state of the domain" overview at the start of an internal engagement.

## Usage

1. Download PingCastle from the official site: https://www.pingcastle.com/download/
2. Copy `PingCastle.exe` and `PingCastle.exe.config` (the config embeds a temporary license automatically) to a Windows machine. It does not need to be domain-joined, but must reach a DC.
3. Run a healthcheck and open the resulting HTML report.

```powershell

# Domain-joined machine
.\PingCastle.exe --healthcheck
# Non-domain-joined machine
.\PingCastle.exe --healthcheck --server "DC_FQDN" --port 389 --user "USER_NAME" --password "USER_PASS"

```

## References

- PingCastle - https://www.pingcastle.com/
