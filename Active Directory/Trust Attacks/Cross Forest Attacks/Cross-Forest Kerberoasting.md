**Cross-Forest Kerberoasting** — request crackable service tickets for accounts in a *different* forest across a trust, so a foothold in one domain hands you passwords in another. A trust is a link that lets users in one forest be recognised by another; because of it, you can ask the target forest's domain controller for a Kerberos service ticket for any account that has an SPN — a Service Principal Name, the label that ties a service to a user account. Part of that ticket is encrypted with the service account's password hash, so you take it offline and brute-force the plaintext, exactly like ordinary Kerberoasting. Mechanically: from the trusted domain you launch the attack against the trusting domain — run `Rubeus.exe kerberoast /domain:target.external /nowrap` to pull the hashes, then crack them with hashcat mode `-m 13100`.

```bash

.\Rubeus.exe kerberoast /domain:target.external /nowrap

```

Copy paste the hashes into `hash.txt` file. Then just crack the hash like in classic Kerberoasting:

```bash

hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt

```