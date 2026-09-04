**Phishing (initial access)** — the tradecraft of getting a foothold by convincing a human to run your payload or hand over credentials/session tokens. This folder covers the delivery techniques, not the C2/implant that follows.

**Note:** For authorized engagements only (a signed scope / rules of engagement). Everything here is dual-use - the Detection & OPSEC sections double as blue-team guidance.

## Methodology

1. **Pretext** - a believable story and sender (see intelligence gathering / OSINT for targets, org lingo, email format).
2. **Infrastructure** - a look-alike domain (optionally categorized/aged), a mail sender with correct SPF/DKIM/DMARC, a redirector in front of the payload/proxy, and TLS. Keep the phishing host separate from long-term C2.
3. **Payload** - pick the vector that survives the target's mail/web controls and **Mark-of-the-Web (MOTW)**. Office macros are largely dead by default; container files, LNKs, HTML smuggling and reverse-proxy credential theft dominate now.
4. **Delivery** - email attachment, link, QR, chat (Teams/Slack), or malvertising/SEO.
5. **Evasion** - MOTW handling, AV/AMSI, sandbox checks, and content that passes secure email gateways.

## MOTW in one paragraph

Files downloaded from the internet get a `Zone.Identifier` alternate data stream (MOTW). Office opens MOTW documents in **Protected View** and blocks macros; SmartScreen scrutinizes MOTW executables. Container formats (ISO/IMG/VHD) and archives historically did **not** propagate MOTW to their contents - the core reason attackers pivoted to them. Treat "does my payload carry MOTW when the victim runs it?" as the central design question.

## Techniques in this folder

**Payload / execution:**
- [Malicious Office Macros (VBA)](Malicious%20Office%20Macros%20%28VBA%29.md) - classic VBA, now mostly blocked by default.
- [Remote Template Injection](Remote%20Template%20Injection.md) - a clean `.docx` that pulls a macro-laden remote template.
- [HTML Smuggling](HTML%20Smuggling.md) - JavaScript assembles the payload client-side to slip past mail filters.
- [ISO and Container Files](ISO%20and%20Container%20Files.md) - ISO/IMG/VHD to defeat MOTW; usually wraps a LNK.
- [LNK Payloads](LNK%20Payloads.md) - shortcut files that run cmd/PowerShell.
- [ClickFix](ClickFix.md) - fake CAPTCHA/error that makes the victim paste a command into Run.

**Credential / token theft:**
- [Evilginx (MFA Phishing Proxy)](Evilginx%20%28MFA%20Phishing%20Proxy%29.md) - reverse-proxy that captures credentials **and** session cookies (MFA bypass).
- [Device Code Phishing](Device%20Code%20Phishing.md) - abuse the Microsoft/Entra OAuth device-code flow to capture tokens.
- [Browser-in-the-Browser (BitB)](Browser-in-the-Browser%20%28BitB%29.md) - a fake OAuth popup window drawn inside the page.
- [Credential Harvesting (GoPhish)](Credential%20Harvesting%20%28GoPhish%29.md) - classic web-clone landing pages + campaign tracking.
- [QR Code Phishing (Quishing)](QR%20Code%20Phishing%20%28Quishing%29.md) - a QR to dodge URL filters and pivot to a mobile device.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- MITRE ATT&CK - Phishing (T1566) - https://attack.mitre.org/techniques/T1566/
- Microsoft - Macros from the internet blocked by default - https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked
