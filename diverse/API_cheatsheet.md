# API Cheatsheet

## REST

### prep for REST

Proxy all API requests through Burp and look for abnormal behaviour.

### recon REST

If some api is found or suspected then enumerate those common paths.

```bash

    /api
    /swagger/index.html
    /openapi.json
    /api/swagger/v1
    /api/swagger
    /api
```

But this is only for REST.


#### js files

Investingate with `JS Link Finder BApp`.

### attack REST

1. try different content sing `Content type converter in Burp`