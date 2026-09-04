**PingCastle** — quickly scores an Active Directory's security posture and flags common misconfigurations. Good for a fast "state of the domain" overview at the start of an internal engagement.

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
