#!/usr/bin/python3

def print_module_help():
        print("""
 --------------------------------------------------------------------------------------------
 + Basic Module                                                                            +  
 --------------------------------------------------------------------------------------------
  CRTL+L                      - clear screen
  sysinfo                     - see basic information about the host
  lcd {path}                  - changes the current local directory to {path}
  exit                        - terminates the server process (and this session)
  lput {src_file, dst_path}   - uploads a local file to the dst_path (dst_path = default current dir)
  lget {file}                 - downloads pathname to the current local dir
  ! {cmd}                     - executes a local shell cmd
  cat                         - view file contents
  ls                          - you should know this, will show hidden files 
 --------------------------------------------------------------------------------------------
 + Process Accounting                                                                      +
 --------------------------------------------------------------------------------------------
  av                        - looks for Anti-Virus solutions running in the process list
  defender                  - query Microsoft Defender status
  vmcheck                   - attempts to detect if we are running in a vm
  securitytools             - looks for security researcher tools in the process list 
 --------------------------------------------------------------------------------------------
 + Credential Harvesting                                                                    +
 --------------------------------------------------------------------------------------------
  unattend                   - find all unattended files (potential base64 credentials)
  regrip                     - save sam, security, system to target pwd
  creds                      - enumerate LSA Protection, WDigest, Credential Guard, Cached 
                               logon count 
 --------------------------------------------------------------------------------------------
 + Tunneling                                                                               + 
 --------------------------------------------------------------------------------------------
  showtun                   - see all tunnels
  addtun                    - add tunnel --> addtun lport rhost rport --> 10000 10.0.0.1 443
  deltun                    - delete tunnel --> deltun lport --> deltun 11000  
 --------------------------------------------------------------------------------------------
 + Collection                                                                               +
 --------------------------------------------------------------------------------------------
  loggrab                   - collects log of your choice --> loggrab Security.evtx 
  survey                    - performs host survey of target, saves output to local machine
 --------------------------------------------------------------------------------------------
 + Priv Esc                                                                                 +
 --------------------------------------------------------------------------------------------
  tokens                    - enumerate enabled tokens for priv esc path
  """)