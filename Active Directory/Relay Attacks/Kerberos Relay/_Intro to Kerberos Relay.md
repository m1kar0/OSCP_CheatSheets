**Kerberos relay** — long thought impossible, Kerberos authentication *can* be relayed (James Forshaw, 2021). Unlike NTLM relay, the trick is not passing a challenge/response along but **controlling which SPN the victim requests a ticket for**, so the service ticket it emits can be replayed against a service you can reach.

## Why Kerberos was thought un-relayable

In the `AP-REQ`, the service ticket is encrypted with the **target service account's** key, and the KDC picks that account from the **SPN the client asked for**. A ticket captured for `cifs/FILESERVER` only decrypts at `FILESERVER` - so naively it cannot be pointed elsewhere. Every Kerberos relay therefore reduces to one problem: **make the victim ask the KDC for a ticket to an SPN that maps to the account running the service you want to relay to.**

## The SPN-control tricks

- **Marshalled target names** (`CredMarshalTargetInfo` / `SecMakeSPNEx2`): SMB appends base64 target-info to the hostname (the `…1UWhRCAAAA…` suffix). The DNS layer resolves the whole crafted name to the attacker's IP, while SSPI strips the suffix and still asks for the *real* SPN - so you receive the auth while the ticket targets the intended service.
- **IP-based SPNs / DNS rebinding**: some clients build the SPN from an attacker-influenced hostname or do a second DNS lookup just for the SPN (Chromium).
- **LLMNR / mDNS multicast poisoning**: answering a multicast name query with a name you chose steers the SPN.
- **OXID resolver / DCOM `SECURITYBINDING` (`aPrincName`)** and **MSRPC `RpcMgmtInqServerPrincName`**: a malicious RPC/DCOM server *dictates* the SPN the client will use - the local "potato"-style trick behind the KrbRelay family.
- **AuthIP GSS-ID payload**: a server-supplied SPN accepted with no validation.

## Universal preconditions

- The **relay target must not enforce signing / channel binding** (you never learn the session key, so you cannot sign) - LDAP signing+CB, SMB signing, or EPA on the AD CS web endpoint each kill the corresponding relay.
- **Clock skew < 5 minutes** (Kerberos requirement).

## Technique matrix

| Direction | Tool | How the SPN is controlled | Usual target(s) | Page |
| --- | --- | --- | --- | --- |
| Local, same host → SYSTEM | KrbRelayUp | local RPC/DCOM forces `NT/SYSTEM` | LDAP (RBCD/ShadowCred), AD CS | [Kerberos Relay to LDAP](Kerberos%20Relay%20to%20LDAP.md) |
| Local, cross-session | KrbRelay | local DCOM, `-session <id>`, CLSID | SMB, LDAP, AD CS | [Kerberos Relay to SMB](Kerberos%20Relay%20to%20SMB.md) |
| Local self-relay → AD CS | KrbRelay / KrbRelay-SMBServer | coerce machine, relay its own auth | HTTP/AD CS | [Kerberos Relay to ADCS](Kerberos%20Relay%20to%20ADCS.md) |
| Remote | RemoteKrbRelay | vulnerable DCOM object on the victim | SMB, LDAP, AD CS, LAPS | ADCS/SMB/LDAP pages |
| Coerced + marshalled DNS | krbrelayx | `CredMarshalTargetInfo` DNS record + coercion | SMB, HTTP/AD CS | [Kerberos Relay to SMB](Kerberos%20Relay%20to%20SMB.md) |
| DNS/IPv6 spoof | krbrelayx + mitm6 | DHCPv6 → rogue DNS → SOA/TKEY | HTTP/AD CS | [mitm6 Kerberos to ESC-8](../mitm6%20relay/Kerberos%20to%20ESC-8%20relay.md) |

**Note - krbrelayx has two distinct modes, do not conflate them:** (1) **TGT capture** using an unconstrained-delegation account's key + coercion - that is the [Unconstrained delegation](../../Trust%20Attacks/Intra%20Forest%20Attacks/Unconstrained%20delegation%20-%20Child%20to%20Parent%20DC.md) attack, not a relay; (2) **Kerberos relay** (no creds needed), used on the SMB/AD CS pages here.

## The big gotcha: DCOM hardening

Since the DCOM hardening rollout (CVE-2021-26414, enforced ~Nov 2022) packet integrity is required on DCOM, so the **local** KrbRelay/KrbRelayUp COM trick can generally only relay to targets that enforce **no** signing at all - in practice **HTTP/AD CS**. Local relays to LDAP/SMB frequently fail on patched hosts. This is the single most common "why doesn't it work anymore" cause.

**Note:** Reflective/cross-protocol Kerberos relay is still evolving (e.g. CVE-2025-58726, CVE-2026-26128); public tooling for the newest variants is incomplete.

## References

- James Forshaw / Google Project Zero - Using Kerberos for Authentication Relay Attacks - https://projectzero.google/2021/10/using-kerberos-for-authentication-relay.html
- The Hacker Recipes - Kerberos relay - https://www.thehacker.recipes/ad/movement/kerberos/relay
- Compass Security - Three-Headed Potato Dog - https://blog.compass-security.com/2024/09/three-headed-potato-dog/
- Microsoft - Detecting and preventing KrbRelayUp - https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/
