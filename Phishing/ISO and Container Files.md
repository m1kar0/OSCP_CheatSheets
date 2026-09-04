**ISO and container files (ISO / IMG / VHD / VHDX)** — package your payload inside a disk-image container. When the victim double-clicks the container it auto-mounts as a drive, and the files inside historically do **not** inherit Mark-of-the-Web (MOTW) - so the LNK/executable inside runs without Protected View or SmartScreen friction.

## How it works

Container formats are mounted, not extracted, by Windows. MOTW is applied to the downloaded `.iso`/`.img`/`.vhd` itself, but the propagation to mounted contents was long absent - the reason these replaced macros as the go-to delivery wrapper. You typically place a **visible [LNK](LNK%20Payloads.md)** plus hidden helper files (payload DLL/EXE, decoy document) inside.

**Note:** Microsoft has been closing this gap - recent Windows builds propagate MOTW to files inside ISO/mounted images. Test against the target's patch level; VHD/VHDX and ISO behave differently across versions.

## Setup

Build a container that holds a LNK + hidden payload with a single tool:

```bash

# PackMyPayload - wrap files into iso/img/vhd/zip/... containers
python3 PackMyPayload.py payload_dir/ invoice.iso
python3 PackMyPayload.py payload_dir/ invoice.img --hide payload.dll

```

Manual ISO on Linux:

```bash

mkdir iso && cp Invoice.lnk payload.dll decoy.pdf iso/
genisoimage -o invoice.iso -J -r iso/        # or mkisofs / xorriso

```

Inside the container:
- `Invoice.lnk` - visible, runs `powershell`/`rundll32` against the hidden payload (see [LNK Payloads](LNK%20Payloads.md)).
- `payload.dll`/`.exe` - hidden (`attrib +h`), executed by the LNK.
- optional decoy document opened for plausibility.

## Delivery

- Attach the container, or (to avoid attachment scanning) deliver it via [HTML Smuggling](HTML%20Smuggling.md) so it lands in Downloads without a scanned network transfer.
- Name it to match the pretext (`Invoice_2026.iso`, `Report.img`).

## Detection & OPSEC

- Users double-mounting an ISO from email is anomalous - defenders alert on `explorer.exe`/mount events for image files from Downloads, and on LNK-in-ISO spawning script hosts.
- Prefer a LNK inside (not a bare EXE) - stealthier icon/pretext and flexible command line.
- Blue team: block/inspect ISO/IMG/VHD mail attachments; hunt `Windows-Defender`/Operational logs for image mounts followed by `powershell`/`rundll32`; recent Windows applies MOTW inside - keep patched.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- PackMyPayload - https://github.com/mgeeky/PackMyPayload
- TrustedSec - MOTW and container files - https://trustedsec.com/blog
