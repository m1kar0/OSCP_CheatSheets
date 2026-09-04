**BloodHound ingestors** — collectors that run as any domain user to gather publicly readable AD information and feed it into [BloodHound](BloodHound.md).

## BloodHound.py (Linux)

Easiest from a Linux box, but less accurate than SharpHound.

```bash

# pip package name: "bloodhound"
bloodhound-python --zip -c All,LoggedOn -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN' -ns 'DNS_IP' -dc 'DC_FQDN' --dns-tcp
# Example:
# bloodhound-python --zip -c All,LoggedOn -u 'Dummy' -p 'SuperP@ss123' -d domain.local -ns 10.0.0.1 -dc dc1.domain.local --dns-tcp

```

- `All` covers every collection method except `LoggedOn`.
- `-ns`, `-dc`, `--dns-tcp` are not strictly required.
- Use `--dns-tcp` when running through a SOCKS proxy (otherwise it resolves names over UDP).

## ADExplorer (Windows)

Very effective against large environments (tested on ~850,000 objects). AD Explorer is part of Sysinternals.

1. Open AD Explorer and connect to a DC with your credentials.
2. `File > Create Snapshot...` and choose the output path.
3. Copy the snapshot to your machine.

Convert the snapshot to BloodHound JSON with `ADExplorerSnapshot.py`:

```bash

ADExplorerSnapshot.py -m BloodHound ADEXPLORER_SNAPSHOT_FILE.dat

```

Even on a large domain this takes only a couple of minutes.

## SharpHound (Windows)

A .NET executable that runs from a domain-joined or non-joined Windows machine. Usually richer than BloodHound.py, but you must get it past AV/EDR.

```batch

REM Domain-joined + domain user session
SharpHound.exe
REM Non-joined machine, explicit LDAP credentials
SharpHound.exe --Domain DOMAIN --ldapusername USER_NAME --ldappassword USER_PASS
REM Non-joined machine on the network: spawn a shell as a domain user, then run SharpHound
runas /netonly /user:DOMAIN\USER_NAME cmd

```

**Note:** With `runas /netonly`, `whoami` still shows your local user - the credentials are used only for network authentication.

## Caution

By default the ingestors enumerate every domain computer and connect to each to list active sessions. This is noisy and often flagged by IDS/IPS - usually acceptable during an internal pentest.

## References

- BloodHound.py - https://github.com/fox-it/BloodHound.py
- SharpHound - https://github.com/BloodHoundAD/SharpHound
- AD Explorer - https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
- ADExplorerSnapshot.py - https://github.com/c3c/ADExplorerSnapshot.py
- The Hacker Recipes - BloodHound - https://www.thehacker.recipes/ad/recon/bloodhound
