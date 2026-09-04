**QR code phishing (quishing)** — put your phishing link inside a **QR code** image instead of a normal clickable URL. Since many email security scanners rewrite and reputation-check text URLs but never decode images, the link hidden in the QR sails past them untouched. It also steers the victim onto their **personal phone** — usually less defended than a work PC (no endpoint monitoring/EDR, a narrow mobile address bar that hides the real domain, and the corporate MFA app conveniently right there) — where they scan it and land on your credential-harvesting or proxy page.

## How it works

1. The lure (email, PDF, poster, or Teams message) shows a QR code with a pretext: "scan to view the secure document / re-enable MFA / read the voicemail".
2. The victim scans with their phone camera and is taken to your phishing page - a [credential harvester](Credential%20Harvesting%20%28GoPhish%29.md) or [Evilginx](Evilginx%20%28MFA%20Phishing%20Proxy%29.md) proxy.
3. On mobile the truncated URL bar and habitual trust make the look-alike domain harder to spot; the corporate secure email gateway never saw a URL to rewrite.

Often embedded in a **PDF/image attachment** so there is no raw link in the mail body at all.

## Setup

Encode your phishing URL into a QR:

```bash

# qrencode
qrencode -o lure.png "https://login.DOMAIN/o365/<lure-path>"
# python
python3 -c "import qrcode; qrcode.make('https://login.DOMAIN/...').save('lure.png')"

```

Embed `lure.png` in a branded PDF/email. Point the URL at your harvesting or proxy infrastructure.

## Delivery

- Email with the QR inside a PDF/image (defeats body-URL scanning).
- Physical pretext (posters, "parking payment", fake MFA-enrollment flyers) for on-site engagements.
- Pair the destination with [Evilginx](Evilginx%20%28MFA%20Phishing%20Proxy%29.md) to capture the mobile session including MFA.

## Detection & OPSEC

- **Blue team:** gateways that OCR/decode QR images in attachments; user awareness ("treat QR codes like links"); mobile MDM + phishing-resistant MFA; flag mail with QR images and little text.
- **Offense:** mobile browsers hide the full domain - a plausible subdomain (`login.DOMAIN`) is often enough; test that your page renders well on mobile.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- qrencode - https://fukuchi.org/works/qrencode/
- CISA - QR code phishing guidance - https://www.cisa.gov/
