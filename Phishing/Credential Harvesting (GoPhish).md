**Credential harvesting (GoPhish)** — the classic approach: a cloned login page on a look-alike domain that simply records whatever the victim types, wrapped in a campaign framework (**GoPhish**) that handles the mailing, tracking, and reporting. Simple and reliable, but it only captures the password - it does **not** beat MFA (use [Evilginx](Evilginx%20%28MFA%20Phishing%20Proxy%29.md) for that).

## How it works

GoPhish orchestrates a phishing campaign end to end: sending profile (SMTP), email template (the lure), landing page (the cloned site that captures input, optionally forwarding to the real site), target groups, and a results dashboard with open/click/submit tracking.

## Setup / Infrastructure

```bash

# Run GoPhish (admin UI on :3333, phishing server on :80/443)
./gophish
# first-run admin password is printed to the console log

```

Then in the admin UI (or API):
1. **Sending Profile** - your SMTP relay; set a plausible From and correct SPF/DKIM/DMARC on the sending domain.
2. **Landing Page** - *Import Site* to clone the real login page; tick **Capture Submitted Data** (+ **Capture Passwords**), and set **Redirect to** the real site after submit (so the victim thinks they mistyped).
3. **Email Template** - the lure; use `{{.URL}}`, `{{.FirstName}}`, and `{{.Tracker}}` (1×1 open pixel).
4. **Users & Groups** - import targets (CSV).
5. **Campaign** - tie the pieces together, set the phishing **URL** (your look-alike domain), launch, and watch results.

Put a **redirector** (Apache mod_rewrite / nginx) in front of GoPhish to filter sandboxes/scanners and hide the real server.

## Delivery

- GoPhish sends the templated email; the link carries a per-target tracker so opens/clicks/submits are attributed.
- Captured credentials appear in the campaign results; the victim is redirected to the genuine site post-submit.

## Detection & OPSEC

- GoPhish's default HTTP responses/headers (e.g. a known server banner and the `X-Gophish` artifacts) are fingerprintable - front it with a redirector and strip/alter headers.
- **Blue team:** look-alike domains in certificate transparency; the tracking pixel and cloned-page origins; users submitting corporate creds to an external domain; enforce phishing-resistant MFA so a captured password is not enough.
- Test SPF/DKIM/DMARC alignment so the lure reaches the inbox rather than spam.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- GoPhish - https://github.com/gophish/gophish
- GoPhish documentation - https://docs.getgophish.com/
