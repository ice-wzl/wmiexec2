# wmiexec2.0
## Overview
- `wmiexec2.0` is the same `wmiexec` that everyone knows and loves (debatable).  
- This 2.0 version is obfuscated to avoid well known signatures from various AV engines.  
- It also has a handful of additional built in modules to help automate some common tasks on Red team engagements.  
- This script is under active development and is currently at a minimal viable product stage.  
- If you find and issue or want a specific module throw me a PR. 
- Enjoy 
## Installation
- **Do not** `wget` this file with `GitHubs Raw` feature, it will break the Ghost emoji. Git clone the repo and it will all work.
- Install `impacket` like you normally would and then download this script.  The installation of `impacket` will resolve any and all dependencies.  If you do not know how to install `impacket` check out this link (or their repo).
- https://ice-wzl.gitbook.io/oscp-prep/domain-controllers/impacket-install 
- https://github.com/fortra/impacket
## Modules 
## Help 
- To view the help and available modules:
- ![mods](https://user-images.githubusercontent.com/75596877/217378727-77c423c0-312a-47ef-90dd-cf4b3acf2804.png)
## Connection
- You can still connect to the remote machine the exact same way.
- Recommend you use `-shell-type powershell` 
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
- ![sysinfo](https://user-images.githubusercontent.com/75596877/217378824-d1c3035c-ded6-44bf-88dc-66185ad46a62.png)
## Psp
- View some well known security products running on the target system.
- ![psp](https://user-images.githubusercontent.com/75596877/217379644-57029cef-0651-4017-ae31-6c0f48e33597.png)
## unattend
- There are 11 files (that I know of) part of the `unattend` group in Windows that have the potential to have base64 encoded credentials in them. Find them all in one command
- ![unattend](https://user-images.githubusercontent.com/75596877/217379773-ef4ce892-d961-4aa4-9bda-5ebe40b171a0.png)
## Regrip
- Save off the `SAM`, `Security` and `System` hives to your local machines.  Defender blocks this by default, so I had to find a bypass working as of 2/7/23.  Try to not get this signatured, thanks in advance.
- ![regrip](https://user-images.githubusercontent.com/75596877/217379936-deee6179-238b-4a80-b342-e29e1a4e865b.png)
## Tunneling
- Leverage Windows built in `netsh` tunneling without having to type the whole thing out 
- See picture for usage options
- ![tuns](https://user-images.githubusercontent.com/75596877/217380037-21698459-fe6d-42d5-90f2-41463681a525.png)
## Loggrab
- This module isnt working right now, if someone knows how to fix it please let me know with a PR.
- Under active development
## Survey
- Also under active development
- Right now run this module and it will run a basic host survey and save it off to your local machine in a file called `survey.txt` as to not flood you with `stdout`
- ![survey](https://user-images.githubusercontent.com/75596877/217380259-d394762c-892a-4b02-8caa-510a5583e8eb.png)
