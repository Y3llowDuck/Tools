# nic3r

> A nicer ASPX web shell — because they're all ugly.

---

## What is it

**nic3r** is a single-file ASPX web shell with a dark terminal UI. Drop the `.aspx` file onto an IIS server and you get a clean, browser-based command interface with zero dependencies and zero setup. Perfect for OSCP or OSEP exam situations where you need a web shell. So you can perform further Windows enumeration or even obtain a fully interactive reverse shell.

It supports two execution modes selectable per command — classic `cmd.exe` and PowerShell — and renders output in a scrollable `<pre>` block so even verbose results stay readable.

---

## Features

- Single `.aspx` file — upload and go, nothing else needed
- `cmd.exe` and `PowerShell` modes, switchable from the dropdown
- PowerShell runs with `-Sta -Nop -NonInteractive -WindowStyle Hidden` for clean output
- Scrollable output block with a capped max height
- Dark terminal aesthetic with CSS custom properties and `Share Tech Mono` font
- No frameworks, no dependencies, no callbacks

---

## Screenshots

**PowerShell mode — `Get-Date`**

![PowerShell Get-Date](https://raw.githubusercontent.com/Y3llowDuck/nic3r/main/date.png)

**cmd mode — `whoami`**

![cmd whoami](https://raw.githubusercontent.com/Y3llowDuck/nic3r/main/whoami.png)

---

## Usage

1. Drop `nic3r1.aspx` onto a writable IIS path.
2. Browse to it.
3. Type a command, select `cmd` or `PowerShell` from the dropdown, and hit **Run**.

```
http://<target>/nic3r1.aspx
```

---

## Customization

The color scheme lives entirely in CSS custom properties at the top of the file, making it trivial to retheme:

```css
:root {
  --bg: #0a0c10;
  --accent:  #f78166;
  --accent2: #79c0ff;
  --accent3: #56d364;
}
```

---

## ⚠️ Disclaimer

This tool is for **authorized penetration testing and CTF environments only**. Do not deploy on systems you do not own or have explicit written permission to test. Unauthorized use is illegal.

---

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
