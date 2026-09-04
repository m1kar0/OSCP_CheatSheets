**Kerberos delegation** lets a service act on behalf of a user against another service (the classic "double hop"). Misconfigured delegation is one of the most reliable escalation-to-Domain-Admin paths in AD. There are four abusable variants; this folder collects them.

## The four types

| Type | Configured attribute | Abuse in one line | Page |
| --- | --- | --- | --- |
| **Unconstrained** | `TrustedForDelegation` | Coerce a DC to auth to a host you control; it caches the DC's TGT | [Unconstrained delegation - Child to Parent DC](../Trust%20Attacks/Intra%20Forest%20Attacks/Unconstrained%20delegation%20-%20Child%20to%20Parent%20DC.md) |
| **Constrained (KCD)** | `msDS-AllowedToDelegateTo` (+ `TrustedToAuthForDelegation`) | Impersonate any user to the allowed SPNs via S4U2proxy | [Constrained Delegation](Constrained%20Delegation.md) |
| **Resource-Based (RBCD)** | `msDS-AllowedToActOnBehalfOfOtherIdentity` on the *target* | Write the attribute on a target you can edit, then impersonate to it | [RBCD Attack](RBCD%20Attack.md) |
| **S4U2self** | any account with an SPN | Use a machine account's key to mint a ticket to itself as an admin | [Computer Account to Local Admin](Computer%20Account%20to%20Local%20Admin.md) |

## Discovery

Enumerate every delegation type in one shot:

```bash

# Linux (impacket)
findDelegation.py 'DOMAIN/USER_NAME:USER_PASS'

```

```powershell

# Windows (PowerView)
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth ; Get-DomainComputer -TrustedToAuth

```

In BloodHound the relevant edges are `AllowedToDelegate` (constrained) and `AllowedToAct` (RBCD); unconstrained hosts show the `Unconstrained Delegation` node property.

**Note:** Domain Controllers have unconstrained delegation by default - that is expected and not the target of these attacks.
