# ByteClipper

A minimalist Bash script to generate a clean, single-line C# reverse https shell payload using `msfvenom`, and copy it directly to your clipboard. Very handy if you need fast and formatted payloads without manual cleanup.

Once executed, the script extracts the shell code , including variable definition and array size, then puts that into your clipboard. I've used it a lot for pasting into .NET loaders or Visual Code C# code.

---

## ✨ Features

- **Generates C# Reverse HTTPS Shell Payload**  
  Uses `msfvenom` to create a `windows/x64/meterpreter/reverse_https` payload.

- **Cleans the Output**  
  Extracts just the byte array from the C# payload and formats it into a one-liner.

- **Clipboard Support**  
  Automatically copies the final result to your clipboard via `xclip`.

- **Lightweight & Fast**  
  A single Bash script that does the job in seconds.

---

## ⚙️ Prerequisites

- [`msfvenom`](https://www.metasploit.com/) – from the Metasploit Framework  
- [`xclip`](https://linux.die.net/man/1/xclip) – clipboard tool for X11 (Linux)  
- Bash shell environment

Install dependencies on Debian/Ubuntu systems:

```bash
sudo apt install metasploit-framework xclip
```

### 2. Make sure the script has right permissions.

```bash
chmod + x byteclipper.sh
```

## Example Output

Here’s an example of what running the script looks like:

![Example Output 1](https://github.com/Y3llowDuck/byteclipper/blob/main/byteclipper1.jpg)

Paste clipboard value to the corresponding line of code:

![Example Output 2](https://github.com/Y3llowDuck/byteclipper/blob/main/byteclipper2.jpg)


