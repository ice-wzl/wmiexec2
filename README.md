# wmiexec2.0
## Overview
- `wmiexec2.0` is the same `wmiexec` that everyone knows and loves (debatable).  
- This 2.0 version is obfuscated to avoid well known signatures from various AV engines.  
- It also has a handful of additional built in modules to help automate some common tasks on Red team engagements.  
- This script is under active development and will improve with time.  
- If you find an issue or want a specific module throw me a PR. 
- Enjoy 
## Installation
- **Do not** `wget` this file with `GitHubs Raw` feature, it will break the Ghost emoji. Git clone the repo and it will all work.
- Install `impacket` like you normally would and then download this script.  The installation of `impacket` will resolve any and all dependencies.  If you do not know how to install `impacket` check out this link (or their repo).
- https://ice-wzl.gitbook.io/oscp-prep/domain-controllers/impacket-install 
- https://github.com/fortra/impacket
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
- ![image](https://user-images.githubusercontent.com/75596877/219784438-cdd4a0f1-9e04-4c22-b0ec-6788b4499b40.png)
## Connection
- You can still connect to the remote machine the exact same way.
- Recommend you use `-shell-type powershell` until I have had further time to test all the modules on both `cmd` and `powershell`
- In the meantime if you are worried about `powershell` logging just downgrade to `powershell 2.0`
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
## My modules
- Everything else from here and below is additional features added into `wmiexec` to make it `wmiexec2.0`
- `cat` - just to make this more unix friendly simply uses `type` on the remote machine to view a file....just an alias you can use
- `ls` || `ls C:\Users` - allows you to view your current target directory. Its executing the `dir /a` command so you will see hidden files by default without any other special options
## Sysinfo
- To see basic target information use this module
- ![sysinfo1](https://user-images.githubusercontent.com/75596877/218882046-dd75ae2b-0ea8-4fe4-b87b-678825b77c15.png)
## Psp
- View some well known security products running on the target system.
- ![psp1](https://user-images.githubusercontent.com/75596877/218882111-b599b867-381b-44b1-b717-780d3c3ed35a.png)
## VMcheck
- Attempts to detect if you are in a virtual machine (So far works for ESXi/VMWare Workstation and QEMU) 
- Performs three checks 
- Looks for `C:\Program Files\VMWare`
- Looks for common running executables in a proccess list
- Pulls the `System Manufactuer` from host
- ![image](https://user-images.githubusercontent.com/75596877/219784824-89f497bf-1426-4f03-8729-ef90b0178515.png)

## unattend
- There are 11 files (that I know of) part of the `unattend` group in Windows that have the potential to have base64 encoded credentials in them. Find them all in one command
- ![unattend1](https://user-images.githubusercontent.com/75596877/218882205-26e6e22a-0b29-4cc1-9009-1fb05b9b7dbf.png)
## Regrip
- Save off the `SAM`, `Security` and `System` hives to your local machines.  Defender blocks this by default, so I had to find a bypass working as of 2/7/23.  Try to not get this signatured, thanks in advance.
- ![regrip1](https://user-images.githubusercontent.com/75596877/218882349-8c7ea3bf-5c14-4e6f-b5e9-7178b573e5a8.png)
## Tunneling
- Leverage Windows built in `netsh` tunneling without having to type the whole thing out 
- See picture for usage options
- ![tuns1](https://user-images.githubusercontent.com/75596877/218882531-aefcacce-de38-418d-9c8e-e9f21a6e6a7a.png)
## Loggrab
- Download log file of your choice
- Will download any file in `C:\windows\system32\winevt\logs`
- Use: `loggrab Security.evtx`
- ![image](https://user-images.githubusercontent.com/75596877/218882689-6ea2c4f3-d037-45f7-9a99-b267ab310281.png)
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

