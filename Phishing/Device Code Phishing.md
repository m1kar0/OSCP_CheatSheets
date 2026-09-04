**Device code phishing** — abuse the legitimate Microsoft/Entra ID **OAuth 2.0 device authorization grant**. You request a device code from Microsoft, send the victim the *real* `microsoft.com/devicelogin` page with your code, and when they sign in (MFA included) to "authorize the device", Microsoft hands **you** the access/refresh tokens. No fake site, no credential capture - the victim authenticates on Microsoft's own domain.

**Note:** Authorized engagements only. This was heavily abused in the wild in 2025 (Storm-2372 via Teams invite lures).

## How it works

1. You POST to Microsoft's `/devicecode` endpoint (as a public first-party client) and receive a `user_code` and `device_code`.
2. You lure the victim to `https://microsoft.com/devicelogin` and get them to enter the `user_code` (short 8-char code) - a genuine Microsoft page, which is what makes the lure convincing.
3. The victim signs in and consents; you poll the `/token` endpoint with the `device_code` and receive access + refresh tokens for the victim.
4. Refresh tokens let you request tokens for other resources; requesting via the **Microsoft Authentication Broker** client id can enable device registration in Entra.

The window is short (the code expires, ~15 min), so lures create urgency ("join the Teams meeting / verify within 15 minutes").

## Setup

Automate the request + polling with a red-team toolkit:

```powershell

# TokenTacticsV2
Import-Module .\TokenTactics.psd1
Get-AzureToken -Client MSGraph           # requests a device code, prints user_code + verification URL, then polls
# -> Browse to https://microsoft.com/devicelogin and enter: XXXXXXXX

```

```bash

# roadtx (ROADtools) - device code flow
roadtx gettokens --device-code

```

Recon the tenant before phishing (confirm it's Entra/Azure AD):

```powershell

# AADInternals
Invoke-AADIntReconAsOutsider -DomainName TARGET_DOMAIN
```

Other tooling: **TokenSmith**, **AADInternals** (`Get-AADIntAccessTokenForXXX -UseDeviceCode`).

## Delivery

- Send the real `https://microsoft.com/devicelogin` link + the code, with a pretext that requires the victim to "authorize" quickly (Teams meeting, document access, MFA re-enrollment).
- The moment the victim consents, your polling loop receives the tokens - use them with Graph/roadtx to enumerate mail, files, and (with the broker client) register a device / obtain a PRT.

## Detection & OPSEC

- **Blue team:** sign-in logs show `Authentication Protocol = Device Code` - alert on device-code sign-ins, especially from unusual locations/first-party clients; Conditional Access can block the device-code flow entirely (a common hardening step); watch for token use from a different IP/ASN than the interactive sign-in.
- **Offense:** the tokens are bound to the client id you requested; refresh where possible; the code is short-lived so time the send.

## References

- The Hacker Recipes - Initial access (phishing) - https://www.thehacker.recipes/infra/phishing
- TrustedSec - Device Code attacks in M365 - https://trustedsec.com/blog/the-new-hotness-in-phishing-device-code-attacks-in-m365
- Huntress - Device code phishing explained - https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained
- TokenTacticsV2 - https://github.com/f-bader/TokenTacticsV2
- AADInternals - https://github.com/Gerenios/AADInternals
