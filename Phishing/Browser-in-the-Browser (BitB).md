**Browser-in-the-Browser (BitB)** — render a **fake browser popup window** entirely inside your phishing page (HTML/CSS/JS drawing a realistic title bar, address bar, and padlock). It imitates the OAuth/SSO "Sign in with Microsoft/Google" popup, so the victim sees a trustworthy-looking `https://login.microsoftonline.com` URL that is actually just text you painted.

## How it works

Legitimate SSO opens a real popup to the identity provider. BitB replaces that with a `<div>` styled to look like a popup window - including a spoofed address bar showing the real IdP URL. The victim types credentials into your form believing it is the genuine provider window. It is most convincing for **OAuth/SSO "continue with" flows** where a popup is expected.

**Limitations:** it is just DOM - it cannot defeat a password manager (which won't autofill on your origin), it can't move outside the real browser window, and it does not by itself capture MFA session cookies (combine with [Evilginx](Evilginx%20%28MFA%20Phishing%20Proxy%29.md) for that). Awareness of BitB has grown since 2022.

## Setup

Use a template and customize the spoofed URL, logo, and form action:

```bash

# mrd0x BITB templates (Chrome/Edge/Firefox, Win/Mac chrome)
git clone https://github.com/mrd0x/BITB
# edit the template: set the fake address-bar text to the IdP, point the form at your collector

```

Host the page on your look-alike domain; wire the credential `POST` to your collector (or proxy through Evilginx to also grab the session).

## Delivery

- Link to a page with a believable "Sign in with Microsoft/Google to continue" button; clicking spawns the fake popup.
- Best paired with a pretext that expects SSO (shared document, meeting, app authorization).

## Detection & OPSEC

- **Tells for users/defenders:** the "popup" cannot be dragged outside the browser window, the address bar is not interactive, and a password manager will not offer to autofill (wrong origin). Maximizing/resizing behavior differs from a real window.
- **Blue team:** user-awareness training on SSO popups; FIDO2/WebAuthn (origin-bound) defeats it; monitor look-alike domains via certificate transparency.
- Combine with [Evilginx](Evilginx%20%28MFA%20Phishing%20Proxy%29.md) when you need the authenticated session, not just the password.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- mrd0x - Browser In The Browser attack - https://mrd0x.com/browser-in-the-browser-phishing-attack/
- BITB templates - https://github.com/mrd0x/BITB
